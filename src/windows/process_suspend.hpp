// 全进程挂起 / 恢复，等价于 Arctium 用的 NtSuspendProcess / NtResumeProcess。
//
// 为什么必须用它：Arctium 在 WaitForUnpack 之后、写任何补丁之前先
//     NativeWindows.NtSuspendProcess(processInfo.ProcessHandle);
// 直到所有补丁写完、RemapAndPatch 完成才
//     NativeWindows.NtResumeProcess(processInfo.ProcessHandle);
//
// 我们之前是「边跑边写」：客户端主线程随时可能执行到我们正在改的那几个字节，
// 即使只有几微秒的窗口，也可能命中半条指令 -> EXCEPTION_INTERNAL_ERROR。
// ThreadFreeze 只冻结了我们枚举到的线程，而 NtSuspendProcess 由内核
// 挂起整个进程的线程，语义更彻底。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>

namespace wowmod {
namespace win {

// 挂起进程内所有线程。成功返回 true。
// 失败时（句柄权限不足等）返回 false 并给出原因，调用方应决定是否继续。
bool suspend_process(HANDLE process, std::string* err = nullptr);

// 恢复由 suspend_process 挂起的进程。
bool resume_process(HANDLE process, std::string* err = nullptr);

}  // namespace win
}  // namespace wowmod
#endif
