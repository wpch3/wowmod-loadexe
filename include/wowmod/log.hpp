// 统一日志出口。
//
// 为什么需要它：加载引擎（mod_loader / arctium_patch / scan_images ...）过去
// 直接用 std::printf 汇报进度。这在控制台程序里没问题，但正式应用是
// 窗口程序（SUBSYSTEM:WINDOWS），stdout 根本不存在 —— printf 全部静默
// 失败，用户界面里一个字都看不到，出问题时完全无从判断。
//
// 这里给引擎一个可替换的输出目标：
//   * 默认：写到 stdout（控制台程序 / CLI 保持原样）
//   * 应用：接到日志窗口 + 日志文件上
//
// 仍然保持"纯 C 风格 + 全局锁"，因为引擎那边调用点在多线程里
// （扫描 / 应用补丁 / 状态汇报），而进程只有一个日志窗口。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdarg>
#include <string>

namespace wowmod {

// 日志接收器：整行（不含换行）交给它。
// 传 nullptr 恢复默认（stdout）。
using LogSink = void (*)(const char* line, void* user);

// 设置接收器。线程安全（内部加锁）。
void set_log_sink(LogSink sink, void* user);

// 写一行。fmt 里不要自带结尾换行（会与内部换行重复，但不致命）。
void logf(const char* fmt, ...);

// 直接写一行字符串。
void log_line(const std::string& line);

// 把当前日志同时追加到文件（应用会用到：关掉窗口后还能翻）。
// 传空字符串关闭。失败静默 —— 记日志失败不该影响主流程。
void set_log_file(const std::string& path);

}  // namespace wowmod
