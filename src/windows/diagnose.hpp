// 诊断模式：不修改客户端任何东西，只把事实列出来。
// 目的：不再"盲改"，用数据决定下一步。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>

namespace wowmod {
namespace win {

// 把一份完整诊断写到 out_path（同时打到 stdout）。
// 不分配可执行内存、不写客户端内存、不起线程（除了必要的查询）。
int run_diagnose(HANDLE process, const std::string& out_path);

}  // namespace win
}  // namespace wowmod
#endif
