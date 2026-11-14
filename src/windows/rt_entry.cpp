// wowmod_rt.dll 的入口点。
//
// 两种进入方式都支持：
//   1. 被当作 DLL 加载（LoadLibraryW / 系统注入）：DllMain 走正常流程；
//   2. 被直接跳进来执行（例如启动器用 CreateRemoteThread 指向导出地址）：
//      wowmod_rt_entry 立刻起工作线程并返回，不依赖 DllMain 是否被调用。
//
// 入口点必须在 DllMain 之前/之外也能安全运行，因此这里只做「取模块基址 + 起线程」。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include <windows.h>

// 由 rt_dll.cpp 提供（外部链接）
extern "C" int wowmod_rt_start(void* module_base);

extern "C" __declspec(dllexport) DWORD WINAPI wowmod_rt_entry(void* module_base) {
  // 直接从远程线程进入时，module_base 可能是 nullptr；用地址反查自身模块。
  void* base = module_base;
  if (!base) {
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&wowmod_rt_entry), &self);
    base = self;
  }
  const int rc = wowmod_rt_start(base);
  return rc == 0 ? 1u : 0u;  // 返回非 0 = 已启动（0 留给"失败"）
}
#endif
