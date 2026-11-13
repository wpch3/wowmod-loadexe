// 挂起进程 + LoadLibraryW 远程线程注入。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>

namespace wowmod {
namespace win {
bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err);
}  // namespace win
}  // namespace wowmod
#endif
