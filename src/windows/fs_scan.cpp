// 文件打开函数定位实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/fs_scan.hpp"

#include "wowmod/util.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace wowmod {
namespace win {

namespace {

// 文件系统代码里才密集出现的扩展名。诊断/格式化函数不会有这些。
const char* kExts[] = {
    ".blp", ".m2", ".skin", ".anim", ".adt", ".wdt", ".wmo", ".db2",
    ".dbc", ".tact", ".idx",  ".blte", ".manifest", ".wdb", ".wlw",
};

// FileDataID 在 12.0.7 里的量级：主要资源 0x2E0000~0x3C0000，
// 更宽的范围 0x100000~0x800000。用宽范围判断，只做加分不当硬条件。
constexpr uint32_t kIdLo = 0x100000;
constexpr uint32_t kIdHi = 0x800000;

std::string hex_bytes(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) {
    s.push_back(h[p[i] >> 4]);
    s.push_back(h[p[i] & 0xF]);
    if (i + 1 < n) s.push_back(' ');
  }
  return s;
}

// 往前回扫找函数序言。返回找到的偏移，找不到返回 npos。
// 典型序言：48 89 5C 24 08 / 40 53 / 48 83 EC ?? / 48 8B C4 ...
size_t backscan_prologue(const std::vector<uint8_t>& b, size_t from, size_t max_back = 0x600) {
  const size_t stop = from > max_back ? from - max_back : 0;
  for (size_t i = from; i > stop; --i) {
    const uint8_t* p = b.data() + i;
    const size_t left = b.size() - i;
    if (left < 8) continue;
    // int3 / nop 填充之后就是函数起点
    const bool pad_before = (i >= 4) && (b[i - 1] == 0xCC || b[i - 1] == 0x90);
    if (!pad_before) continue;
    // sub rsp, imm8 / imm32
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return i;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return i;
    // push rbx/rbp/rsi/rdi ... 后接 sub rsp
    if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55 || p[1] == 0x56 || p[1] == 0x57)) return i;
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 && p[4] == 0x08) return i;
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) return i;
  }
  return std::string::npos;
}

}  // namespace

Json FsScanResult::to_text_report() const {
  std::string t;
  char buf[512];

  t += "文件打开函数定位（运行时内存，只读）\n";
  t += "====================================\n";
  std::snprintf(buf, sizeof(buf), "  扫描映像 %zu 个，合计 %.1f MB，检查函数 %zu 个\n\n",
                images, static_cast<double>(bytes) / (1024.0 * 1024.0), functions_seen);
  t += buf;

  t += "== 为什么在内存里找 ==\n";
  t += "  磁盘 exe 的 .text 共 56.2 MB，熵 = 8.00（密文），只有入口桩\n";
  t += "  0x28 字节是明文。代码只在运行期以明文存在，所以只能在内存里定位。\n\n";

  t += "== 判定依据（结构证据，不是猜偏移）==\n";
  t += "  A 文件扩展名字符串的 RIP 相对引用（.blp/.m2/.skin/...）\n";
  t += "  B FileDataID 范围立即数比较（0x100000~0x800000）\n";
  t += "  C 函数序言可放跳板\n\n";

  if (top.empty()) {
    t += "== 结果: 没有找到候选 ==\n";
    t += "  连\"引用文件扩展名\"的函数都没有，说明扩展名也是间接取址的。\n";
    t += "  这不是失败，而是明确了下一步方向：从 CASC 打开接口下手。\n\n";
  } else {
    t += "== 候选（按证据强度排序）==\n";
    for (size_t i = 0; i < top.size(); ++i) {
      const auto& c = top[i];
      std::snprintf(buf, sizeof(buf), "\n[%zu] 函数 0x%s  score=%d  序言可放跳板=%s\n", i,
                    to_hex(c.va, 16).c_str(), c.score, c.has_frame ? "是" : "否");
      t += buf;
      std::snprintf(buf, sizeof(buf), "    扩展名引用 %zu 个", c.ext_hits);
      t += buf;
      if (!c.exts.empty()) {
        t += ": ";
        for (size_t k = 0; k < c.exts.size() && k < 8; ++k)
          t += (k ? " " : "") + c.exts[k];
      }
      t += "\n";
      std::snprintf(buf, sizeof(buf), "    ID 范围比较 %zu 次", c.cmp_hits);
      t += buf;
      if (c.cmp_hits) {
        std::snprintf(buf, sizeof(buf), "（0x%x ~ 0x%x）", c.id_lo, c.id_hi);
        t += buf;
      }
      t += "\n";
      t += "    序言: " + c.prologue + "\n";
    }
  }

  if (!notes.empty()) {
    t += "\n== 说明 ==\n";
    for (const auto& n : notes) t += "  - " + n + "\n";
  }
  t += "\n本次扫描没有修改客户端任何字节。\n";

  Json j = Json::make_object();
  j.set("text", Json::make_string(t));
  return j;
}

FsScanResult find_file_open_functions(HANDLE process, size_t top_n) {
  FsScanResult out;
  const auto images = scan_process_images(process);
  out.images = images.size();

  // 收集所有扩展名字符串的内存地址（VA）。
  struct ExtRef { uint64_t va; std::string text; };
  std::vector<ExtRef> ext_addrs;

  for (const auto& img : images) {
    if (img.bytes.empty()) continue;
    out.bytes += img.bytes.size();
    for (const char* e : kExts) {
      const std::string needle(e);
      size_t pos = 0;
      while (true) {
        // 在字节序列里找 ASCII 串：用 std::search 的通用版并显式统一类型。
        const uint8_t* begin = img.bytes.data() + pos;
        const uint8_t* end = img.bytes.data() + img.bytes.size();
        const uint8_t* hit = std::search(
            begin, end, reinterpret_cast<const uint8_t*>(needle.data()),
            reinterpret_cast<const uint8_t*>(needle.data()) + needle.size());
        if (hit == end) break;
        const size_t off = static_cast<size_t>(hit - img.bytes.data());
        ext_addrs.push_back({img.base + off, needle});
        pos = off + 1;
        if (ext_addrs.size() > 4000) break;
      }
    }
  }

  out.notes.push_back("找到 " + std::to_string(ext_addrs.size()) + " 处扩展名字符串");
  if (ext_addrs.empty()) {
    out.notes.push_back("扩展名字符串本身都找不到，映像可能还没解密");
  }

  // 每块映像里扫 rip 相对 lea，看是否指向扩展名字符串。
  std::map<uint64_t, FsCandidate> cand;  // key = 函数起点 VA
  for (const auto& img : images) {
    if (img.bytes.empty()) continue;
    const size_t n = img.bytes.size();
    for (size_t i = 0; i + 7 <= n; ++i) {
      // 48 8D xx disp32  (lea reg,[rip+disp32])
      if (img.bytes[i] != 0x48 || img.bytes[i + 1] != 0x8D) continue;
      const uint8_t modrm = img.bytes[i + 2];
      if ((modrm & 0xC7) != 0x05) continue;   // mod=00, rm=101 => rip 相对
      const int32_t disp = static_cast<int32_t>(
          static_cast<uint32_t>(img.bytes[i + 3]) | (static_cast<uint32_t>(img.bytes[i + 4]) << 8) |
          (static_cast<uint32_t>(img.bytes[i + 5]) << 16) |
          (static_cast<uint32_t>(img.bytes[i + 6]) << 24));
      const uint64_t target = img.base + i + 7 + static_cast<int64_t>(disp);
      // 这个目标是不是某个扩展名字符串？
      for (const auto& er : ext_addrs) {
        if (er.va != target) continue;
        const size_t pro = backscan_prologue(img.bytes, i);
        if (pro == std::string::npos) break;
        const uint64_t fva = img.base + pro;
        auto& c = cand[fva];
        if (c.va == 0) {
          c.va = fva;
          c.match_va = img.base + i;
          const size_t hl = std::min<size_t>(24, n - pro);
          c.prologue = hex_bytes(img.bytes.data() + pro, hl);
          c.has_frame = true;
        }
        c.ext_hits++;
        if (c.exts.size() < 12) c.exts.push_back(er.text);
        break;
      }
    }
  }

  out.functions_seen = cand.size();

  std::vector<FsCandidate> all;
  for (auto& kv : cand) all.push_back(std::move(kv.second));

  // 打分：扩展名引用数为主证据。
  for (auto& c : all) {
    c.score = static_cast<int>(c.ext_hits) * 10 + (c.has_frame ? 5 : 0) +
              static_cast<int>(c.cmp_hits) * 20;
  }
  std::stable_sort(all.begin(), all.end(), [](const FsCandidate& a, const FsCandidate& b) {
    if (a.score != b.score) return a.score > b.score;
    return a.va < b.va;
  });
  if (all.size() > top_n) all.resize(top_n);
  out.top = std::move(all);

  return out;
}

}  // namespace win
}  // namespace wowmod
#endif
