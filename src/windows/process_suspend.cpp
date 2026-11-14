// 全进程挂起 / 恢复。见 process_suspend.hpp。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/process_suspend.hpp"

#include <cstdio>

namespace wowmod {
namespace win {
namespace {

using NtSuspendProcessFn = LONG(WINAPI*)(HANDLE);
using NtResumeProcessFn = LONG(WINAPI*)(HANDLE);

struct Api {
  NtSuspendProcessFn suspend = nullptr;
  NtResumeProcessFn resume = nullptr;
};

const Api& api() {
  static Api a = []() -> Api {
    Api r{};
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return r;
    r.suspend = reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(ntdll, "NtSuspendProcess"));
    r.resume = reinterpret_cast<NtResumeProcessFn>(GetProcAddress(ntdll, "NtResumeProcess"));
    return r;
  }();
  return a;
}

}  // namespace

bool suspend_process(HANDLE process, std::string* err) {
  if (!process) {
    if (err) *err = "无效的进程句柄";
    return false;
  }
  const auto& a = api();
  if (!a.suspend) {
    if (err) *err = "ntdll!NtSuspendProcess 不可用";
    return false;
  }
  const LONG st = a.suspend(process);
  if (st != 0) {
    char b[128];
    std::snprintf(b, sizeof(b), "NtSuspendProcess 失败, NTSTATUS=0x%08lX",
                  static_cast<unsigned long>(st));
    if (err) *err = b;
    return false;
  }
  return true;
}

bool resume_process(HANDLE process, std::string* err) {
  if (!process) {
    if (err) *err = "无效的进程句柄";
    return false;
  }
  const auto& a = api();
  if (!a.resume) {
    if (err) *err = "ntdll!NtResumeProcess 不可用";
    return false;
  }
  const LONG st = a.resume(process);
  if (st != 0) {
    char b[128];
    std::snprintf(b, sizeof(b), "NtResumeProcess 失败, NTSTATUS=0x%08lX",
                  static_cast<unsigned long>(st));
    if (err) *err = b;
    return false;
  }
  return true;
}

}  // namespace win
}  // namespace wowmod
#endif
