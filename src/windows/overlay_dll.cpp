// wowmod_hook.dll —— 被注入到客户端进程的覆盖层。
// 初始化顺序很重要：先读完所有配置/文件，再安装 hook，避免自递归。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include <windows.h>

#include <string>

#include "windows/fileid_hook.hpp"
#include "windows/iat_hook.hpp"
#include "windows/mem_scan.hpp"
#include "windows/runtime.hpp"

namespace {

using namespace wowmod::win;

volatile LONG g_init_status = 0;  // 0=initializing, 1=runtime ready, -1=init failed, 2=probe only

// 诊断脚本/加载器会在自身进程里 LoadLibraryW 本 DLL 再 FreeLibrary；
// 探测模式只验证 Windows loader 能否映射 DLL，不运行 overlay 初始化。
bool probe_only() { return GetEnvironmentVariableW(L"WOWMOD_PROBE", nullptr, 0) != 0; }

bool initialize(HMODULE self) {
  if (!init_runtime(self)) { dlog("runtime init failed"); return false; }

  std::string err;
  if (!install_iat_hooks(self, &err)) dlog("IAT hook: " + err);
  else dlog("IAT hook: " + err);

  const auto& plan = runtime().hooks;
  if (plan.mode == "fileid") {
    std::string h_err;
    if (!install_fileid_hook(plan, &h_err)) {
      dlog("fileid hook 未启用: " + h_err + "；继续以通用 VFS 模式运行");
    } else {
      dlog("fileid hook: " + h_err);
    }
  } else {
    dlog("纯 VFS 模式: " + plan.reason);
  }

  // 加密壳客户端：磁盘 .text 是密文，静态找不到 hook 点时，
  // 在后台等壳解密完成后扫描进程内存，产出候选特征（默认不自动下断点）。
  start_runtime_scan();
  return true;
}

DWORD WINAPI initialize_worker(void* p) {
  bool ok = initialize(static_cast<HMODULE>(p));
  InterlockedExchange(&g_init_status, ok ? 1 : -1);
  return ok ? 0 : 1;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    if (probe_only()) {
      InterlockedExchange(&g_init_status, 2);
      return TRUE;
    }
    // DllMain 在 Windows loader lock 下运行。配置读取、文件 I/O、IAT 修改、
    // 扫描线程创建都移到 worker；不能在 DllMain 里等待它完成。
    HANDLE worker = CreateThread(nullptr, 0, initialize_worker, hModule, 0, nullptr);
    if (worker) CloseHandle(worker);
    else InterlockedExchange(&g_init_status, -2);
  }
  return TRUE;
}

extern "C" {

// 便于诊断：启动器/调试器可以调用这些导出函数确认注入成功。
__declspec(dllexport) const char* WINAPI wowmod_version() { return "wowmod-loadexe 1.0.0"; }

__declspec(dllexport) int WINAPI wowmod_overlay_count() {
  return runtime().ready ? static_cast<int>(runtime().vfs.effective_entries().size()) : -1;
}

__declspec(dllexport) int WINAPI wowmod_client_build() {
  return runtime().ready ? runtime().ci.build : -1;
}

__declspec(dllexport) const char* WINAPI wowmod_hook_mode() {
  return runtime().ready ? runtime().hooks.mode.c_str() : "not-initialized";
}

// 0=初始化中，1=运行时配置/Hook 安装步骤完成，-1=runtime 初始化失败，
// -2=无法创建初始化线程，2=诊断探测模式（主动跳过 overlay 初始化）。
__declspec(dllexport) LONG WINAPI wowmod_init_status() { return InterlockedCompareExchange(&g_init_status, 0, 0); }

// 供 SetWindowsHookEx 注入机制使用：user32 会在目标 GUI 线程收到消息时
// 自动把本 DLL 加载进那个进程（不经过 CreateRemoteThread / LoadLibraryW 远程调用）。
__declspec(dllexport) LRESULT CALLBACK wowmod_hook_proc(int code, WPARAM w, LPARAM l) {
  return CallNextHookEx(nullptr, code, w, l);
}

}  // extern "C"
#endif
