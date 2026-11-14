// 在运行时（已解密）映像里定位「按 FileDataID 打开文件」的函数。
//
// 为什么必须在内存里做：磁盘 exe 的 .text 熵 = 8.00（56.2 MB 全是密文），
// 只有入口桩 0x28 字节是明文。代码只在运行期以明文存在。
//
// 本模块不猜、不套用 10.x 的偏移，只用**可验证的结构证据**：
//   A. 函数里出现「文件扩展名字符串」的 RIP 相对引用（.blp/.m2/.skin/...）
//      —— 这是文件系统代码独有的，诊断/日志函数不会有这么多。
//   B. 函数里有 FileDataID 范围的立即数比较（WoW 的 ID 在 0x2e0000 量级）。
//   C. 函数序言是常规的 push/栈帧分配（可安全放置跳板）。
// 输出 top 候选 + 各自的证据明细，供人判断，绝不声称"已找到"。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/json.hpp"
#include "windows/scan_images.hpp"

namespace wowmod {
namespace win {

struct FsCandidate {
  uint64_t va = 0;             // 函数起点（已往前回扫到序言）
  uint64_t match_va = 0;       // 证据所在地址
  size_t ext_hits = 0;         // 命中的文件扩展名字符串个数
  std::vector<std::string> exts;
  size_t cmp_hits = 0;         // FileDataID 范围立即数比较次数
  uint32_t id_lo = 0, id_hi = 0;
  int score = 0;
  std::string prologue;        // 前 24 字节 hex
  bool has_frame = false;      // 是否是常规函数序言（可放跳板）
};

struct FsScanResult {
  size_t images = 0;
  size_t bytes = 0;
  size_t functions_seen = 0;
  std::vector<FsCandidate> top;
  std::vector<std::string> notes;
  Json to_text_report() const;
};

// 只读扫描，不改目标任何字节。top_n 控制返回几个候选。
FsScanResult find_file_open_functions(HANDLE process, size_t top_n = 10);

}  // namespace win
}  // namespace wowmod
#endif
