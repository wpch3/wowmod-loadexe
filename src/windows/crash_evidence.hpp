// 崩溃现场检查器（跨进程，只读）。
//
// 为什么必须有这个：
//   探针装上去之后客户端崩了，崩溃码是 0xC00000E5（STATUS_ILLEGAL_INSTRUCTION）。
//   但我们【无法证明】崩的那条指令是不是我们改的那 14 字节 —— 那只是推断。
//   没有证据就只能猜，下次还会崩。
//
//   所以这里做一件很朴素的事：崩溃发生时，把崩溃线程的 RIP 记下来，
//   然后和"我们改过的地址"做区间比较，直接给出是/否。
//   如果是"否"，就说明问题不在 hook 而在别处，省得继续瞎改。
//
// 信息从哪来：Windows 的 "fatal error" 弹窗通常由 WerFault 产生。
//   即使拿不到完整的 minidump，WER 也会在
//     %LOCALAPPDATA%\CrashDumps\           (WER 本地转储)
//     %LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive\
//   留下 c00000e5 相关记录。这里只读，不写任何东西。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

// 一次崩溃的原始线索（能拿到多少填多少，拿不到的字段保持 0/空）。
struct CrashEvidence {
  bool found = false;                 // 是否找到了崩溃
  uint32_t exception_code = 0;        // 例如 0xC00000E5
  uint64_t rip = 0;                   // 崩溃指令地址
  uint64_t faulting_address = 0;      // ExceptionInformation[1]
  uint32_t thread_id = 0;
  std::string source;                 // 线索来源（转储文件路径 / 报告名）
  std::string note;
};

// 在常见目录里找【最新的】c00000e5 相关转储，并解析出 RIP。
// game_dir 用于额外扫客户端自己的 Errors/ 与 Logs/ 目录。
CrashEvidence find_latest_illegal_instruction_crash(const std::string& game_dir);

// 判定：崩溃地址是否落在我们改过的字节区间里。
// 返回 0 = 不相关 / 1 = 落在我们的跳转区间内 / 2 = 落在我们的跳板或 trampoline 内。
int classify_crash_address(const CrashEvidence& ev,
                           const std::vector<std::pair<uint64_t, uint64_t>>& hooked_ranges,
                           const std::vector<std::pair<uint64_t, uint64_t>>& stub_ranges);

// 生成一段人类可读的结论，直接打印给用户看。
std::string describe_crash_verdict(const CrashEvidence& ev, int verdict);

// 解析 minidump 里的 EXCEPTION_STREAM（只读流目录，不依赖 dbghelp）。
bool parse_minidump_exception(const std::string& path, CrashEvidence* out, std::string* err);

}  // namespace win
}  // namespace wowmod
#endif
