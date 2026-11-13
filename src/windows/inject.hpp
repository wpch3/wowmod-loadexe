// 多机制注入：CreateRemoteThread(LoadLibraryW) / NtCreateThreadEx / QueueUserAPC。
// 成功与否一律以「目标进程模块表里有没有 wowmod_hook.dll」为准，不看线程退出码。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct InjectReport {
  bool success = false;
  std::string method;
  std::vector<std::string> attempts;   // 每种方法的结果，便于排错
};

// main_thread 用于 APC 注入；allow_apc=false 时跳过该方法（挂起阶段用不上）。
InjectReport inject_dll(HANDLE process, HANDLE main_thread, bool allow_apc,
                        const std::wstring& dll_path, const std::vector<std::string>& methods);

// 给启动器用的模块表查询（APC / Windows 钩子注入都靠它做最终判定）。
bool is_module_loaded(HANDLE process, const std::wstring& dll);

// 兼容旧调用的薄封装（不再使用，仅保留给测试/文档引用）。
bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err);

}  // namespace win
}  // namespace wowmod
#endif
