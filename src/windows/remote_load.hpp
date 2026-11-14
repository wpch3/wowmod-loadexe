// 把 wowmod_rt.dll 送进目标进程的三条路径（按可靠性排序）。
//
// 背景：在这个 Firestorm 构建上，挂起状态下 CreateRemoteThread(LoadLibraryW)
// 会**成功创建线程并返回退出码 0**，也就是 LoadLibraryW 返回了 NULL。
// 光看"退出码 0"无法区分是：
//   (a) 目标里缺 CRT DLL（api-ms-win-crt-*）导致加载失败；
//   (b) DLL 自身初始化失败；
//   (c) 系统加载器被拦截。
// 所以这里改成：线程里返回 LoadLibraryW 的真实返回值 + GetLastError，
// 再依次尝试其它路径。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct LoadAttempt {
  std::string method;      // 用的是什么办法
  bool ok = false;
  uint64_t module_base = 0;
  uint32_t last_error = 0;
  std::string detail;
};

// 单次远程调用的结果（能带回两个 64 位值）
struct RemoteCallResult {
  bool ran = false;
  bool timed_out = false;
  uint64_t r0 = 0;
  uint64_t r1 = 0;
};

// 在目标进程里执行 fn(arg0, arg1, arg2)，并取回 rax/rdx。
// 用一个很小的 x64 壳代码包一层，把 DLL 的导出函数当成普通函数调用。
RemoteCallResult call_remote(HANDLE process, uint64_t fn, uint64_t arg0, uint64_t arg1,
                             uint64_t arg2, DWORD timeout_ms, std::string* err);

// 路径 1：CreateRemoteThread + LoadLibraryW。
// 返回真实模块基址；失败时 detail 里带 GetLastError。
LoadAttempt load_by_remote_loadlibrary(HANDLE process, const std::string& dll_path);

// 路径 2：手工映射（不经过系统加载器、不进模块表、不跑 DllMain）。
// 适用于目标进程拒绝远程线程、或系统加载器被拦截的情况。
// 成功后可以直接调用映像里的导出函数（PE32+，支持 DIR64 重定位和导入表）。
LoadAttempt load_by_manual_map(HANDLE process, const std::string& dll_path);

// 路径 3：在目标进程里用 NtCreateThreadEx（绕过部分 CreateRemoteThread 限制）。
LoadAttempt load_by_nt_create_thread(HANDLE process, const std::string& dll_path);

// 依次尝试，返回第一个成功的；把每一次的结果都写进 attempts。
LoadAttempt load_runtime(HANDLE process, const std::string& dll_path,
                          std::vector<LoadAttempt>* attempts);

}  // namespace win
}  // namespace wowmod
#endif
