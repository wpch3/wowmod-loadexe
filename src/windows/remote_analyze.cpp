// 远程分析实现：启动器侧读目标进程内存 -> 本地分析 -> 写报告。
// 不加载任何模块进客户端，因此不会触发 0x1100。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "remote_analyze.hpp"

#include <tlhelp32.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "wowmod/analyze.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

bool readable_protect(DWORD p) {
  if (p & PAGE_GUARD) return false;
  switch (p & 0xFF) {
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

// 分块读一块区域；读不到的部分保持 0。
size_t read_region(HANDLE process, uint64_t base, size_t size, std::vector<uint8_t>* out) {
  out->assign(size, 0);
  size_t total = 0;
  for (size_t off = 0; off < size; off += (1u << 20)) {
    SIZE_T got = 0;
    const size_t n = (std::min)(static_cast<size_t>(1u << 20), size - off);
    if (ReadProcessMemory(process, reinterpret_cast<const void*>(base + off), out->data() + off,
                          n, &got)) {
      total += got;
    }
  }
  return total;
}

size_t count_markers(const std::vector<uint8_t>& buf, std::string* first) {
  size_t hits = 0;
  for (const auto& m : loose_file_markers()) {
    if (m.text.empty() || m.text.size() > buf.size()) continue;
    if (std::search(buf.begin(), buf.end(), m.text.begin(), m.text.end()) != buf.end()) {
      ++hits;
      if (first && first->empty()) *first = m.text;
    }
  }
  return hits;
}

bool write_text(const std::string& path, const std::string& text) {
  HANDLE h = CreateFileW(utf8_to_wide(to_native_path(path)).c_str(), GENERIC_WRITE,
                         FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD w = 0;
  WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &w, nullptr);
  CloseHandle(h);
  return true;
}

void ensure_dir(const std::string& dir) {
  CreateDirectoryW(utf8_to_wide(to_native_path(dir)).c_str(), nullptr);
}

}  // namespace

namespace {

// 关键：以前所有进度都攒在一个 std::string 里，函数返回后才一次性打印。
// 用户看到"第 1 次尝试 ---"之后一片空白，以为卡死，其实是在跑。
// 这里改成一个"边写边打印"的日志器。
class LiveLog {
 public:
  explicit LiveLog(std::string* sink) : sink_(sink) {}
  // 设置进度文件路径：每条日志立刻追加写入磁盘。
  // 这样即使整个流程卡死或被杀，也能从文件里看到它停在哪一行。
  void set_progress_file(const std::string& p) { progress_path_ = p; }
  LiveLog& operator+=(const std::string& s) {
    if (sink_) *sink_ += s;
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
    if (!progress_path_.empty()) {
      HANDLE h = CreateFileW(utf8_to_wide(to_native_path(progress_path_)).c_str(),
                             FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, s.data(), static_cast<DWORD>(s.size()), &w, nullptr);
        CloseHandle(h);
      }
    }
    return *this;
  }
  LiveLog& operator+=(const char* s) { return *this += std::string(s); }
 private:
  std::string* sink_;
  std::string progress_path_;
};

// 目标进程的主模块信息（exe 的基址与 SizeOfImage）。
// 用途：真实解密后的客户端数据块，大小必然接近 SizeOfImage。
// 这是比"标记命中数"可靠得多的判据 —— 之前按命中数排序，
// 结果选中了【我们自己注入的 DLL】（它的 .rdata 里存着全部标记字符串，
// 7 个全中），而不是客户端。
struct MainModuleInfo {
  uint64_t base = 0;
  uint32_t size_of_image = 0;
  size_t module_count = 0;
  std::vector<std::pair<uint64_t, uint64_t>> ranges;  // 所有模块的 [base, end)
};

MainModuleInfo query_main_module(HANDLE process) {
  MainModuleInfo mi;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                         GetProcessId(process));
  if (snap == INVALID_HANDLE_VALUE) return mi;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      const uint64_t b = reinterpret_cast<uint64_t>(me.modBaseAddr);
      if (mi.base == 0) {  // 快照里第一个就是主模块
        mi.base = b;
        mi.size_of_image = me.modBaseSize;
      }
      mi.ranges.push_back({b, b + me.modBaseSize});
      ++mi.module_count;
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return mi;
}

bool is_all_zero(const uint8_t* p, size_t n) {
  // 按 8 字节比较，比逐字节快 8 倍
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t v = 0;
    std::memcpy(&v, p + i, 8);
    if (v) return false;
  }
  for (; i < n; ++i)
    if (p[i]) return false;
  return true;
}

bool in_any_module(const MainModuleInfo& mi, uint64_t base) {
  for (const auto& r : mi.ranges) {
    if (base >= r.first && base < r.second) return true;
  }
  return false;
}

}  // namespace

namespace {

struct RegionInfo {
  uint64_t base;
  size_t size;
  DWORD protect;
  bool exec;
};

// 读区域开头，判断它是不是一个「已映射的 PE 映像」。
// 这是最可靠的判据：解密后的客户端一定以 MZ 开头，
// 且 OptionalHeader.SizeOfImage 与区域大小吻合。
struct PeProbe {
  bool is_mz = false;
  bool is_pe = false;
  uint32_t size_of_image = 0;
  uint32_t entry_rva = 0;
  uint64_t image_base_field = 0;
  uint16_t sections = 0;
  // 入口点落在可执行节内 —— 这是"完整内存映像"的强证据
  bool entry_in_code = false;
  // 所有节名都能读出来（不是全 0）—— 说明节表没被抹掉
  bool sections_named = false;
  uint16_t code_sections = 0;
};

PeProbe probe_pe(HANDLE process, uint64_t base) {
  PeProbe p;
  uint8_t hdr[0x400] = {0};
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), hdr, sizeof(hdr), &got) ||
      got < 0x40)
    return p;
  if (hdr[0] != 'M' || hdr[1] != 'Z') return p;
  p.is_mz = true;
  uint32_t lfanew = 0;
  std::memcpy(&lfanew, hdr + 0x3C, 4);
  if (static_cast<size_t>(lfanew) + 0x40 > sizeof(hdr)) return p;
  if (std::memcmp(hdr + lfanew, "PE\0\0", 4) != 0) return p;
  p.is_pe = true;
  const uint8_t* fh = hdr + lfanew + 4;
  std::memcpy(&p.sections, fh + 2, 2);
  const uint8_t* oh = fh + 20;
  const uint16_t magic = static_cast<uint16_t>(oh[0] | (oh[1] << 8));
  if (magic != 0x20B) return p;  // 只认 PE32+
  std::memcpy(&p.entry_rva, oh + 16, 4);
  std::memcpy(&p.image_base_field, oh + 24, 8);
  std::memcpy(&p.size_of_image, oh + 56, 4);

  // ---- 节表完整性：判断这块到底是"完整内存映像"还是"只剩数据/头" ----
  //
  // 为什么重要：Firestorm 会同时保留多份同尺寸的映像副本，其中有些只有
  // 数据段、没有可执行节。挑错副本的直接后果就是「字符串找得到、但一个
  // RIP 相对引用都没有」——看起来像分析算法坏了，其实是挑错了目标。
  {
    // 节表紧跟可选头：offset = lfanew + 4 + 20 + SizeOfOptionalHeader
    const uint16_t opt_size = static_cast<uint16_t>(fh[16] | (fh[17] << 8));
    const size_t sh_off =
        static_cast<size_t>(lfanew) + 4 + 20 + static_cast<size_t>(opt_size);
    size_t named = 0, code_sections = 0;
    for (uint16_t i = 0; i < p.sections; ++i) {
      const size_t eo = sh_off + static_cast<size_t>(i) * 40;
      if (eo + 40 > sizeof(hdr)) break;
      const uint8_t* e = hdr + eo;
      bool any = false;
      for (int k = 0; k < 8; ++k)
        if (e[k] >= 0x20 && e[k] < 0x7F) { any = true; break; }
      if (any) ++named;
      uint32_t va = 0, vsize = 0, chars = 0;
      std::memcpy(&vsize, e + 8, 4);
      std::memcpy(&va, e + 12, 4);
      std::memcpy(&chars, e + 36, 4);
      const bool code = (chars & 0x20000000u) != 0;
      if (code) ++code_sections;
      if (code && p.entry_rva >= va && p.entry_rva < va + (vsize ? vsize : 0x1000))
        p.entry_in_code = true;
    }
    p.sections_named = (p.sections > 0 && named == p.sections);
    p.code_sections = static_cast<uint16_t>(code_sections);
  }
  return p;
}

}  // namespace

RemoteImagePick fetch_client_image(HANDLE process, std::vector<uint8_t>* out, size_t max_bytes,
                                   std::string* log) {
  RemoteImagePick best;
  if (!out) return best;
  LiveLog L(log);

  const MainModuleInfo mi = query_main_module(process);
  {
    L += "  主模块 0x" + to_hex(mi.base, 16) + " SizeOfImage " +
            std::to_string(mi.size_of_image >> 20) + " MB，模块 " +
            std::to_string(mi.module_count) + " 个\n";
  }

  // ---- 枚举区域 ----
  std::vector<RegionInfo> regions;
  MEMORY_BASIC_INFORMATION mbi;
  uint64_t addr = 0;
  const uint64_t limit = 0x7FFFFFFF0000ull;
  while (addr < limit &&
         VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
    const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    const size_t size = mbi.RegionSize;
    if (size == 0) break;
    addr = base + size;
    if (mbi.State != MEM_COMMIT) continue;
    if (!readable_protect(mbi.Protect)) continue;
    if (size < (4u << 20)) continue;
    const bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    regions.push_back({base, size, mbi.Protect, exec});
  }
  L += "  可读区域 " + std::to_string(regions.size()) + " 个（>=4MB）\n";

  // ---- 第一优先：带 MZ/PE 头、且 SizeOfImage 与区域大小吻合的区域 ----
  //
  // 之前的判据错了：我要求"可执行"，但 Firestorm 解密后的客户端映像
  // 是 MAPPED + PAGE_READWRITE（0x004），【不可执行】。
  // 于是它被我的过滤条件排除，程序转头去扫别的区域，永远找不到。
  // 现在直接认 PE 头，这是唯一不会误判的判据。
  struct Cand { size_t idx; PeProbe pe; int score; };
  std::vector<Cand> pe_cands;
  for (size_t i = 0; i < regions.size(); ++i) {
    const auto pe = probe_pe(process, regions[i].base);
    if (!pe.is_pe) continue;
    // size_of_image 与区域大小接近 -> 这就是完整映像
    const size_t soi = pe.size_of_image;
    const size_t rsize = regions[i].size;
    int score = 0;
    if (soi && rsize >= soi * 8 / 10 && rsize <= soi * 12 / 10) score += 100;
    if (mi.size_of_image && soi && soi == mi.size_of_image) score += 50;
    if (regions[i].exec) score += 10;
    // 决定性判据：有可执行节、入口点落在里面、节名完好 -> 这才是完整映像。
    // 缺这些的副本会"字符串找得到但一个引用都没有"，必须排后面。
    if (pe.sections_named) score += 60;
    if (pe.code_sections > 0) score += 40;
    if (pe.entry_in_code) score += 40;
    pe_cands.push_back({i, pe, score});
    {
      L += "  PE 映像 0x" + to_hex(regions[i].base, 16) + "  区域 " +
              std::to_string(rsize >> 20) + " MB  SizeOfImage " +
              std::to_string(soi >> 20) + " MB  入口 RVA 0x" + to_hex(pe.entry_rva, 1) +
              "  节数 " + std::to_string(pe.sections) +
              "  代码节 " + std::to_string(pe.code_sections) +
              "  入口在代码段 " + (pe.entry_in_code ? "是" : "否") +
              "  节名完好 " + (pe.sections_named ? "是" : "否") + "  " +
              (regions[i].exec ? "可执行" : "数据") + "  score=" + std::to_string(score) + "\n";
    }
  }
  std::sort(pe_cands.begin(), pe_cands.end(),
            [](const Cand& a, const Cand& b) { return a.score > b.score; });

  // 优先尝试得分最高的 PE 映像
  for (const auto& c : pe_cands) {
    const auto& r = regions[c.idx];
    L += "  读取 PE 映像 0x" + to_hex(r.base, 16) + "（" +
         std::to_string(r.size >> 20) + " MB）...\n";
    L += "    [进度] ";
    const size_t want = (std::min)(r.size, max_bytes);
    out->assign(want, 0);
    size_t total = 0;
    // 按 256KB 分块读：块越小越能定位"卡在哪个偏移"。
    // 每 4MB 打一行进度（带偏移），这样即使卡住，进度文件里也能看到最后位置。
    std::vector<uint8_t> chunk(256u << 10);
    const DWORD read_start = GetTickCount();
    size_t next_report = 0;
    for (size_t off = 0; off < want; off += chunk.size()) {
      SIZE_T got = 0;
      const size_t n = (std::min)(chunk.size(), want - off);
      const DWORD block_start = GetTickCount();
      const BOOL ok = ReadProcessMemory(process, reinterpret_cast<const void*>(r.base + off),
                                        out->data() + off, n, &got);
      const DWORD block_ms = GetTickCount() - block_start;
      if (ok) total += got;

      if (off >= next_report) {
        L += "      " + std::to_string(off >> 20) + " MB / " +
             std::to_string(want >> 20) + " MB";
        if (block_ms > 200) L += "（本块耗时 " + std::to_string(block_ms) + " ms）";
        L += "\n";
        next_report = off + (4u << 20);
      }
      // 任何一块超过 5 秒，立刻停止并说明偏移
      if (block_ms > 5000) {
        L += "    偏移 0x" + to_hex(off, 1) + " 读取超过 5 秒，放弃（该页可能未驻留）\n";
        break;
      }
      if (GetTickCount() - read_start > 45000) {
        L += "    总读取超过 45 秒，放弃\n";
        break;
      }
    }
    L += "    读回 " + std::to_string(total >> 20) + " MB / " +
         std::to_string(want >> 20) + " MB\n";
    if (total < 4096) continue;
    if (total < want) out->resize(total);

    std::string first;
    best.marker_hits = count_markers(*out, &first);
    best.base = r.base;
    best.size = out->size();
    best.first_marker = first;
    best.ok = true;
    if (log) {
      *log += "  读回 " + std::to_string(out->size() >> 20) + " MB，标记命中 " +
              std::to_string(best.marker_hits) +
              (first.empty() ? "（无标记，可能是被剥离或不在前面）" : "（首个: " + first + "）") +
              "\n";
    }
    // 有标记就用它；没标记也先记下来，继续找带标记的
    if (best.marker_hits > 0) return best;
    // 保留这个候选，继续找更好的
    break;
  }

  // 先记下"最好的 PE 候选"（后面 regions 会被重排，索引会失效，所以这里拷贝出来）
  RegionInfo pe_fallback{0, 0, 0, false};
  if (!pe_cands.empty()) pe_fallback = regions[pe_cands[0].idx];

  // ---- 第二优先：边读边搜标记 ----
  const auto& markers = loose_file_markers();
  std::vector<uint8_t> chunk(1u << 20);
  std::vector<uint8_t> carry;
  const size_t kCarry = 64;
  std::sort(regions.begin(), regions.end(), [](const RegionInfo& a, const RegionInfo& b) {
    if (a.exec != b.exec) return a.exec;
    return a.size > b.size;
  });

  size_t searched_mb = 0, read_fail = 0, zero_blocks = 0;
  for (size_t ri = 0; ri < regions.size(); ++ri) {
    const auto& r = regions[ri];
    if (log) {
      *log += "  [" + std::to_string(ri) + "/" + std::to_string(regions.size()) + "] 0x" +
              to_hex(r.base, 16) + " " + std::to_string(r.size >> 20) + " MB" +
              (r.exec ? " 可执行" : " ") + " ... ";
      std::fflush(stdout);
    }
    const size_t per_region_cap = (max_bytes < (256u << 20)) ? max_bytes : (256u << 20);
    const size_t region_cap = (std::min)(r.size, per_region_cap);
    bool found_here = false;
    std::string found_marker;
    const DWORD region_start = GetTickCount();

    for (size_t off = 0; off < region_cap && !found_here; off += chunk.size()) {
      if (GetTickCount() - region_start > 20000) break;
      SIZE_T got = 0;
      const size_t n = (std::min)(chunk.size(), region_cap - off);
      if (!ReadProcessMemory(process, reinterpret_cast<const void*>(r.base + off), chunk.data(),
                             n, &got) ||
          got < 64) {
        ++read_fail;
        continue;
      }
      if (is_all_zero(chunk.data(), got)) ++zero_blocks;
      searched_mb += got >> 20;
      std::vector<uint8_t> window;
      window.reserve(carry.size() + got);
      window.insert(window.end(), carry.begin(), carry.end());
      window.insert(window.end(), chunk.begin(), chunk.begin() + got);
      for (const auto& m : markers) {
        if (m.text.empty()) continue;
        if (std::search(window.begin(), window.end(), m.text.begin(), m.text.end()) !=
            window.end()) {
          found_here = true;
          found_marker = m.text;
          break;
        }
      }
      if (!found_here) {
        const size_t keep = (std::min)(kCarry, window.size());
        carry.assign(window.end() - keep, window.end());
      }
    }

    if (!found_here) {
      if (log) *log += "无标记\n";
      if (searched_mb > 4096) {
        if (log) *log += "  已扫超过 4GB，停止\n";
        break;
      }
      continue;
    }

    const size_t want = (std::min)(r.size, max_bytes);
    out->assign(want, 0);
    size_t total = 0;
    for (size_t off = 0; off < want; off += chunk.size()) {
      SIZE_T got = 0;
      const size_t n = (std::min)(chunk.size(), want - off);
      if (ReadProcessMemory(process, reinterpret_cast<const void*>(r.base + off),
                            out->data() + off, n, &got)) {
        total += got;
      }
    }
    if (total) out->resize(total);
    best.base = r.base;
    best.size = out->size();
    best.first_marker = found_marker;
    best.marker_hits = count_markers(*out, nullptr);
    best.ok = true;
    if (log) *log += "命中 [" + found_marker + "]，读回 " + std::to_string(out->size() >> 20) +
                      " MB\n";
    return best;
  }

  if (log) {
    *log += "  所有区域都没有找到标记字符串\n";
    *log += "  统计: 读取失败 " + std::to_string(read_fail) + " 块, 全零 " +
            std::to_string(zero_blocks) + " 块\n";
  }
  // 退一步：找到了带 PE 头的映像但里面没有标记字符串。
  // 这种情况下仍然把映像读回来 —— 至少能跑 FileDataID 查找函数扫描，
  // 而且报告里能看到真实的入口 RVA 和节表，方便继续定位。
  if (pe_fallback.size) {
    const size_t want = (std::min)(pe_fallback.size, max_bytes);
    out->assign(want, 0);
    size_t total = 0;
    std::vector<uint8_t> chunk(1u << 20);
    for (size_t off = 0; off < want; off += chunk.size()) {
      SIZE_T got = 0;
      const size_t n = (std::min)(chunk.size(), want - off);
      if (ReadProcessMemory(process, reinterpret_cast<const void*>(pe_fallback.base + off),
                            out->data() + off, n, &got)) {
        total += got;
      }
    }
    if (total >= 4096) {
      if (total < want) out->resize(total);
      best.base = pe_fallback.base;
      best.size = out->size();
      best.marker_hits = 0;
      best.first_marker.clear();
      best.ok = true;
      best.note = "映像里有 PE 头但没有 loose-file 标记字符串";
      if (log) {
        *log += "  退一步：使用 PE 映像 0x" + to_hex(pe_fallback.base, 16) + "（" +
                std::to_string(out->size() >> 20) + " MB，无标记）\n";
      }
    }
  }
  return best;
}

WriteProbe probe_write_capability(HANDLE process) {
  WriteProbe p;
  // 1) 普通可写块
  void* rw = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (rw) {
    p.alloc_rw = true;
    // 2) 写进去
    uint64_t magic = 0x574D4F44;
    SIZE_T w = 0;
    p.write_ok = WriteProcessMemory(process, rw, &magic, sizeof(magic), &w) && w == sizeof(magic);
    // 3) 改保护属性
    DWORD old = 0;
    p.protect_ok = VirtualProtectEx(process, rw, 0x1000, PAGE_EXECUTE_READ, &old) != FALSE;
    VirtualFreeEx(process, rw, 0, MEM_RELEASE);
  } else {
    p.detail += "VirtualAllocEx(RW) 失败,";
  }
  // 4) 可执行块（hook 跳板必须放这里）
  void* rx = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
  if (rx) {
    p.alloc_rx = true;
    VirtualFreeEx(process, rx, 0, MEM_RELEASE);
  } else {
    p.detail += "VirtualAllocEx(RWX) 失败(可能禁了动态代码),";
  }
  if (p.detail.empty()) p.detail = "全部可用";
  return p;
}

// 针对【真实的 hook 目标页】做探测：能不能给它改保护、跨不跨页。
// 这一步是纯只读+改回，不会留下任何改动。
std::string probe_target_page(HANDLE process, uint64_t target, size_t need) {
  char b[512];
  MEMORY_BASIC_INFORMATION mbi{};
  if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(target), &mbi, sizeof(mbi)) == 0) {
    std::snprintf(b, sizeof(b), "目标 0x%llx VirtualQueryEx 失败, GetLastError=%lu",
                  static_cast<unsigned long long>(target), GetLastError());
    return b;
  }
  const uint64_t region_begin = reinterpret_cast<uint64_t>(mbi.BaseAddress);
  const uint64_t region_end = region_begin + mbi.RegionSize;
  const uint64_t page = target & ~static_cast<uint64_t>(0xFFF);
  const size_t in_page = static_cast<size_t>(0x1000 - (target - page));
  const bool crosses = need > in_page;
  const bool fits_region = target + need <= region_end;

  std::string s;
  std::snprintf(b, sizeof(b),
                "目标 0x%llx: State=0x%lx Protect=0x%lx Type=0x%lx 区域[0x%llx,0x%llx) "
                "需要 %zu 字节, 页内剩余 %zu%s, 区域余量 %s",
                static_cast<unsigned long long>(target), static_cast<unsigned long>(mbi.State),
                static_cast<unsigned long>(mbi.Protect), static_cast<unsigned long>(mbi.Type),
                static_cast<unsigned long long>(region_begin),
                static_cast<unsigned long long>(region_end), need, in_page,
                crosses ? " -> 跨越页边界" : "", fits_region ? "足够" : "不足");
  s = b;

  // 真正试着改一下保护再改回（只读探测，不留痕迹）。
  // 顺序与 write_remote 保持一致：MEM_MAPPED 用 PAGE_EXECUTE_WRITECOPY。
  const bool mapped = (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE);
  std::vector<DWORD> cands = mapped
                                 ? std::vector<DWORD>{PAGE_EXECUTE_WRITECOPY, PAGE_WRITECOPY,
                                                      PAGE_READWRITE}
                                 : std::vector<DWORD>{PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
  bool ok = false;
  for (DWORD want : cands) {
    DWORD old = 0;
    if (VirtualProtectEx(process, reinterpret_cast<void*>(target), need, want, &old)) {
      DWORD back = 0;
      VirtualProtectEx(process, reinterpret_cast<void*>(target), need, old, &back);
      std::snprintf(b, sizeof(b), "  [可改保护: 是, 用 0x%lx %s]", static_cast<unsigned long>(want),
                    want == PAGE_EXECUTE_WRITECOPY ? "PAGE_EXECUTE_WRITECOPY"
                                                   : (want == PAGE_READWRITE ? "PAGE_READWRITE"
                                                                             : "RWX"));
      s += b;
      ok = true;
      break;
    }
  }
  if (!ok) {
    const DWORD e = GetLastError();
    std::snprintf(b, sizeof(b), "  [可改保护: 否, GetLastError=%lu]", e);
    s += b;
  }
  return s;
}

int analyze_remote_and_write(HANDLE process, const std::string& out_dir, std::string* log) {
  ensure_dir(out_dir);
  LiveLog L(log);
  L.set_progress_file(join_path(out_dir, "wowmod-progress.log"));
  L += "开始扫描进程内存\n";
  std::vector<uint8_t> image;
  const auto pick = fetch_client_image(process, &image, 384u << 20, log);
  if (!pick.ok) {
    {
      L += "没有找到含 loose-file 标记字符串的内存块。\n";
      *log += "这说明客户端要么还没解密完，要么把字符串去掉了。\n";
      L += "请走到登录界面、停留 10 秒后重试。\n";
    }
    write_text(join_path(out_dir, "wowmod-analysis.txt"), *log);
    return 2;
  }

  L += "选用 0x" + to_hex(pick.base, 16) + "（" + std::to_string(image.size() >> 20) +
       " MB）做分析\n";

  ImageView img;
  img.data = image.data();
  img.size = image.size();
  img.base_va = pick.base;

  AnalyzeOptions opt;
  opt.max_functions = 24;
  // 远程分析必须设预算：108MB 映像上，标记数 × 命中数 会让全盘
  // xref 扫描被调用几十次。这里总共给 60 秒，超时就带着已有结果返回。
  opt.refs_budget_seconds = 60.0;
  opt.id_budget_seconds = 20.0;
  opt.progress = [&L](const std::string& stage, size_t done, size_t total) {
    // 只在阶段开始/结束时打印，避免 7 个标记刷 7 行
    if (done == 0 || done >= total)
      L += "    [" + stage + "] " + std::to_string(done) + "/" + std::to_string(total) + "\n";
  };
  L += "  正在分析（xref + 序言解码 + id 扫描）...\n";
  const auto t_an = std::chrono::steady_clock::now();
  const AnalyzeResult res = analyze_image(img, opt);
  const double an_sec =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t_an).count();
  L += "  分析耗时 " + std::to_string(static_cast<int>(an_sec)) + " 秒\n";
  if (an_sec < 0.5 && res.string_hits.empty() && !res.orphan_strings.empty())
    L += "  （很快且无引用是预期行为：见报告里「数据布局」一节）\n";
  L += "  分析返回\n";

  std::string text;
  text += "wowmod 分析报告\n";
  text += "================\n";
  text += "分析基址: 0x" + to_hex(pick.base, 16) + "\n";
  text += "读取大小: " + std::to_string(image.size()) + " 字节\n";
  text += "命中标记: " + std::to_string(pick.marker_hits) + " 个（首个: " + pick.first_marker +
          "）\n\n";
  text += res.to_text();

  L += "  正在写报告...\n";
  write_text(join_path(out_dir, "wowmod-analysis.txt"), text);
  write_text(join_path(out_dir, "wowmod-analysis.json"), res.to_json().dump(2));

  L += "分析完成: 字符串 " + std::to_string(res.string_hits.size()) + " 个, 推荐 detour " +
       std::to_string(res.detour_targets.size()) + " 个, id 候选 " +
       std::to_string(res.id_candidates.size()) + " 个\n";
  L += "报告已写入 " + join_path(out_dir, "wowmod-analysis.txt") + "\n";
  return res.ok ? 0 : 3;
}

}  // namespace win
}  // namespace wowmod
#endif
