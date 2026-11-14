// 进程内候选映像枚举实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/scan_images.hpp"

#include <tlhelp32.h>
#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>

#include "wowmod/analyze.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

bool readable(DWORD protect) {
  if (protect & PAGE_GUARD) return false;
  if (protect & PAGE_NOACCESS) return false;
  switch (protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

bool executable(DWORD protect) {
  switch (protect & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

struct Region {
  uint64_t base;
  size_t size;
  DWORD protect;
  bool image;    // mbi.Type == MEM_IMAGE：由映像映射而来
  std::string module;
};

std::vector<Region> enumerate_regions(HANDLE p) {
  std::vector<Region> out;
  MEMORY_BASIC_INFORMATION mbi;
  uint64_t addr = 0;
  const uint64_t limit = 0x7FFFFFFF0000ull;  // 用户空间上限
  while (addr < limit && VirtualQueryEx(p, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
    const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    const size_t size = mbi.RegionSize;
    if (size == 0) break;
    if (mbi.State == MEM_COMMIT && readable(mbi.Protect) && !(mbi.Protect & PAGE_GUARD)) {
      Region r;
      r.base = base;
      r.size = size;
      r.protect = mbi.Protect;
      r.image = mbi.Type == MEM_IMAGE;
      out.push_back(std::move(r));
    }
    addr = base + size;
    if (addr <= base) break;
  }
  return out;
}

std::map<uint64_t, std::string> module_map(DWORD pid) {
  std::map<uint64_t, std::string> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE) return out;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      out[reinterpret_cast<uint64_t>(me.modBaseAddr)] = wide_to_utf8(me.szModule);
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return out;
}

size_t count_markers(const uint8_t* p, size_t n, std::string* first) {
  size_t hits = 0;
  for (const auto& m : loose_file_markers()) {
    if (m.text.size() > n) continue;
    const uint8_t* end = p + n;
    const uint8_t* it = std::search(p, end, m.text.begin(), m.text.end());
    if (it != end) {
      ++hits;
      if (first && first->empty()) *first = m.text;
    }
  }
  return hits;
}

}  // namespace

bool process_has_client_markers(HANDLE process, std::string* first_marker) {
  const auto regions = enumerate_regions(process);
  std::vector<uint8_t> chunk(1 << 20);
  for (const auto& r : regions) {
    for (size_t off = 0; off < r.size; off += chunk.size()) {
      const size_t n = std::min(chunk.size(), r.size - off);
      SIZE_T got = 0;
      if (!ReadProcessMemory(process, reinterpret_cast<const void*>(r.base + off), chunk.data(), n,
                             &got) ||
          got < 8)
        continue;
      if (count_markers(chunk.data(), got, first_marker) > 0) return true;
    }
  }
  return false;
}

std::vector<ScannedImage> scan_process_images(HANDLE process, size_t max_bytes) {
  std::vector<ScannedImage> out;
  const auto modules = module_map(GetProcessId(process));
  const auto regions = enumerate_regions(process);

  for (const auto& r : regions) {
    // 只关注「像代码/数据」的区域：可执行，或属于映像，或足够大
    const bool looks_like_image = r.image || r.module.empty() && r.size >= (1u << 20);
    if (!looks_like_image && !executable(r.protect)) continue;
    if (r.size < (64u << 10)) continue;

    ScannedImage img;
    img.base = r.base;
    img.size = r.size;
    img.executable = executable(r.protect);

    // 尽量把同一映像的相邻区域合并成一个连续视图（这里简单处理：单区域）
    const size_t to_read = std::min(r.size, max_bytes);
    img.bytes.assign(to_read, 0);
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(r.base), img.bytes.data(),
                           to_read, &got)) {
      // 整块读不了：逐页读，缺页保持 0
      size_t done = 0;
      for (size_t off = 0; off < to_read; off += 0x1000) {
        SIZE_T g = 0;
        const size_t n = std::min<size_t>(0x1000, to_read - off);
        if (ReadProcessMemory(process, reinterpret_cast<const void*>(r.base + off),
                              img.bytes.data() + off, n, &g))
          done += g;
      }
      got = done;
    }
    if (got < 4096) continue;
    img.bytes.resize(got);
    img.committed_bytes = got;

    // 是否带着 PE 头（内存映像里 PE 头就在 base）
    if (got >= 0x200 && img.bytes[0] == 'M' && img.bytes[1] == 'Z') {
      const uint32_t lfanew = *reinterpret_cast<const uint32_t*>(img.bytes.data() + 0x3C);
      if (lfanew + 0x40 < got &&
          *reinterpret_cast<const uint32_t*>(img.bytes.data() + lfanew) == 0x00004550u) {
        img.has_pe_header = true;
        img.pe_timestamp = *reinterpret_cast<const uint32_t*>(img.bytes.data() + lfanew + 8);
      }
    }
    auto it = modules.find(r.base);
    if (it != modules.end()) img.module_name = it->second;

    img.marker_hits = count_markers(img.bytes.data(), img.bytes.size(), &img.first_marker);
    out.push_back(std::move(img));
  }

  // 优先：含标记 > 有 PE 头 > 可执行 > 更大
  std::sort(out.begin(), out.end(), [](const ScannedImage& a, const ScannedImage& b) {
    if (a.marker_hits != b.marker_hits) return a.marker_hits > b.marker_hits;
    if (a.has_pe_header != b.has_pe_header) return a.has_pe_header;
    if (a.executable != b.executable) return a.executable;
    return a.size > b.size;
  });
  return out;
}

std::vector<DumpResult> dump_client_images(const std::vector<ScannedImage>& images,
                                           const std::string& out_dir, size_t max_images) {
  std::vector<DumpResult> out;
  CreateDirectoryW(utf8_to_wide(to_native_path(out_dir)).c_str(), nullptr);

  // 先按「标记命中数」排序：有客户端标记的才是我们要分析的。
  // 没有标记但足够大的也保留在后面，作为兜底（万一是没识别出的新布局）。
  std::vector<const ScannedImage*> order;
  for (const auto& img : images) {
    if (img.bytes.size() < (1u << 20)) continue;
    order.push_back(&img);
  }
  std::stable_sort(order.begin(), order.end(), [](const ScannedImage* a, const ScannedImage* b) {
    if (a->marker_hits != b->marker_hits) return a->marker_hits > b->marker_hits;
    if (a->has_pe_header != b->has_pe_header) return a->has_pe_header;
    return a->bytes.size() > b->bytes.size();
  });

  size_t idx = 0;
  for (const ScannedImage* pi : order) {
    if (out.size() >= max_images) break;
    const auto& img = *pi;

    DumpResult r;
    r.base = img.base;
    r.marker_hits = img.marker_hits;
    char name[64];
    std::snprintf(name, sizeof(name), "image-%zu-%llx-m%zu.bin", idx++,
                  static_cast<unsigned long long>(img.base), img.marker_hits);
    r.path = join_path(out_dir, name);

    FILE* f = nullptr;
    const std::wstring wpath = utf8_to_wide(to_native_path(r.path));
    if (_wfopen_s(&f, wpath.c_str(), L"wb") != 0 || !f) {
      r.error = "无法创建文件: " + r.path;
      out.push_back(std::move(r));
      continue;
    }
    const size_t n = fwrite(img.bytes.data(), 1, img.bytes.size(), f);
    fclose(f);
    r.written = n;
    r.ok = (n == img.bytes.size());
    if (!r.ok) r.error = "写出不完整";
    out.push_back(std::move(r));
  }
  return out;
}

namespace {

uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// 读目标进程一段内存：整段失败就逐页读，缺页填 0（导出物仍然可用）。
size_t read_into(HANDLE process, uint64_t addr, std::vector<uint8_t>* buf, size_t off, size_t n) {
  if (off + n > buf->size()) return 0;
  SIZE_T got = 0;
  if (ReadProcessMemory(process, reinterpret_cast<const void*>(addr), buf->data() + off, n, &got))
    return static_cast<size_t>(got);
  size_t done = 0;
  for (size_t o = 0; o < n; o += 0x1000) {
    SIZE_T g = 0;
    const size_t m = std::min<size_t>(0x1000, n - o);
    if (ReadProcessMemory(process, reinterpret_cast<const void*>(addr + o), buf->data() + off + o,
                          m, &g))
      done += static_cast<size_t>(g);
  }
  return done;
}

}  // namespace

// 估算一段字节的位熵（0..8）。密文页≈8.0，x64 明文代码≈6.0~6.6。
static double byte_entropy(const uint8_t* p, size_t n) {
  if (!n) return 0.0;
  size_t hist[256] = {0};
  for (size_t i = 0; i < n; ++i) hist[p[i]]++;
  double h = 0.0;
  for (size_t i = 0; i < 256; ++i) {
    if (!hist[i]) continue;
    const double q = static_cast<double>(hist[i]) / static_cast<double>(n);
    h -= q * (q > 0 ? (std::log(q) / std::log(2.0)) : 0.0);
  }
  return h;
}

ModuleDump dump_module_full(HANDLE process, const std::string& module_name,
                            const std::string& out_path) {
  ModuleDump out;
  out.path = out_path;

  // 1) 定位模块基址。
  //
  // 教训：上一版用「第一个 MZ」找主模块，结果导出了 .rsrc 资源段里的一个
  // 16 KB DLL（节表只有 .rdata 0xE0 / .rsrc 0x1894），完全不是主模块。
  // 而且 module_map 靠 CreateToolhelp32Snapshot，在 32 位宿主上枚举 64 位
  // 进程会返回空 —— 这条路本身不可靠。
  //
  // 正确做法：用 VirtualQueryEx 的 mbi.Type == MEM_IMAGE 找「按映像映射」
  // 的区域，再校验 PE 头 + SizeOfImage（主模块一定是最大的那个）。
  uint64_t base = 0;
  const auto mods = module_map(GetProcessId(process));
  // 注意：加壳客户端的「主模块」在诊断报告里是 Type=0x40000(MEM_MAPPED)，
  // 不是 MEM_IMAGE —— 壳把真实的 PE 映射成了文件映射。所以两种都要收，
  // 再靠 PE 头 + SizeOfImage 竞争，而不是靠 Type 判断。
  std::vector<Region> images;
  for (const auto& r : enumerate_regions(process)) {
    if (r.image || r.size >= (16u << 20)) images.push_back(r);
  }

  if (!module_name.empty()) {
    for (const auto& kv : mods) {
      if (kv.second == module_name) { base = kv.first; break; }
    }
    if (!base) {
      out.error = "模块表里找不到: " + module_name +
                  "（模块表可能因跨位数枚举而不可用）";
      return out;
    }
  } else {
    // 主模块 = SizeOfImage 最大的那个 MEM_IMAGE 区域。
    uint32_t best = 0;
    for (const auto& r : images) {
      std::vector<uint8_t> hdr(0x1000);
      if (read_into(process, r.base, &hdr, 0, 0x1000) < 0x400) continue;
      if (hdr[0] != 'M' || hdr[1] != 'Z') continue;
      const uint32_t pe_off = rd32(hdr.data() + 0x3C);
      if (pe_off > 0x1000 || rd32(hdr.data() + pe_off) != 0x00004550u) continue;
      const uint16_t mg = rd16(hdr.data() + pe_off + 24);
      const uint32_t soi = rd32(hdr.data() + pe_off + 24 + 56);
      if (mg != 0x20B && mg != 0x10B) continue;
      if (soi > best) { best = soi; base = r.base; }
    }
    if (!base) {
      out.error = "没有找到任何 MEM_IMAGE 区域（客户端可能尚未解密完成）";
      return out;
    }
  }
  out.base = base;

  // 2) 读 PE 头，拿 SizeOfImage 和节表。
  std::vector<uint8_t> hdr(0x1000);
  if (read_into(process, base, &hdr, 0, 0x1000) < 0x400) {
    out.error = "PE 头不可读";
    return out;
  }
  if (hdr[0] != 'M' || hdr[1] != 'Z') { out.error = "基址不是 MZ"; return out; }
  const uint32_t pe_off = rd32(hdr.data() + 0x3C);
  if (pe_off > 0x1000 || rd32(hdr.data() + pe_off) != 0x00004550u) {
    out.error = "PE 签名无效";
    return out;
  }
  const uint16_t nsec = rd16(hdr.data() + pe_off + 6);
  const uint16_t magic = rd16(hdr.data() + pe_off + 24);
  const size_t opt = pe_off + 24;
  const uint32_t size_of_image = rd32(hdr.data() + opt + 56);
  if (size_of_image == 0 || size_of_image > 512u * 1024u * 1024u) {
    out.error = "SizeOfImage 异常";
    return out;
  }
  out.size_of_image = size_of_image;
  const size_t sec_off = opt + (magic == 0x20B ? 240 : 224);

  // 3) 整块按映像导出（RVA == 偏移），缺页填 0。
  //    out_path 为空 = 只探测（采样解密进度），不读整块也不写盘 ——
  //    否则光是轮询一次就要把 113 MB 读一遍。
  std::vector<uint8_t> img;
  if (!out_path.empty()) {
    img.assign(size_of_image, 0);
    out.written = read_into(process, base, &img, 0, size_of_image);
  }

  // 4) 记下节表，供报告核对。
  static const char* kHex = "0123456789abcdef";
  for (uint16_t i = 0; i < nsec && sec_off + i * 40 + 40 <= hdr.size(); ++i) {
    const uint8_t* s = hdr.data() + sec_off + i * 40;
    std::string name(reinterpret_cast<const char*>(s), 8);
    while (!name.empty() && (name.back() == '\0' || name.back() == ' ')) name.pop_back();
    const uint32_t vs = rd32(s + 8), va = rd32(s + 12), ch = rd32(s + 36);
    auto hx = [&](uint32_t v) {
      std::string r(8, '0');
      for (int k = 7; k >= 0; --k) { r[k] = kHex[v & 0xF]; v >>= 4; }
      return std::string("0x") + r;
    };
    out.sections.push_back(name + "  VA=" + hx(va) + "  VS=" + hx(vs) +
                           "  可执行=" + ((ch & 0x20000000u) ? "是" : "否"));
  }

  // 5) 采样 .text，估算明文比例（供调用方判断导出时机）。
  //    只读第一页就知道内容可用不可用，代价远低于整块 113 MB。
  for (uint16_t i = 0; i < nsec && sec_off + i * 40 + 40 <= hdr.size(); ++i) {
    const uint8_t* s = hdr.data() + sec_off + i * 40;
    const uint32_t ch = rd32(s + 36);
    if (!(ch & 0x20000000u)) continue;  // 只看可执行段
    const uint32_t vs = rd32(s + 8), va = rd32(s + 12);
    const size_t pages = vs / 0x1000;
    if (!pages) continue;
    // 均匀抽 256 页，够稳定又不用读满 53 MB。
    const size_t stride = pages > 256 ? pages / 256 : 1;
    std::vector<uint8_t> page(0x1000);
    for (size_t p = 0; p < pages; p += stride) {
      const uint64_t at = base + va + static_cast<uint64_t>(p) * 0x1000;
      if (read_into(process, at, &page, 0, 0x1000) < 0x1000) continue;
      out.text_checked++;
      if (byte_entropy(page.data(), 0x1000) < 7.0) out.text_low_entropy++;
    }
  }

  // 6) 写盘。
  if (out_path.empty()) {
    out.ok = true;   // 探测模式：只回报采样结果
    return out;
  }
  FILE* f = nullptr;
  const std::wstring wpath = utf8_to_wide(to_native_path(out_path));
  if (_wfopen_s(&f, wpath.c_str(), L"wb") != 0 || !f) {
    out.error = "无法创建文件: " + out_path;
    return out;
  }
  const size_t n = fwrite(img.data(), 1, img.size(), f);
  fclose(f);
  out.ok = (n == img.size());
  if (!out.ok) out.error = "写出不完整";
  return out;
}

}  // namespace win
}  // namespace wowmod
#endif
