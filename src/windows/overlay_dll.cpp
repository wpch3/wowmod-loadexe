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

void initialize(HMODULE self) {
  if (!init_runtime(self)) { dlog("runtime init failed"); return; }

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
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    initialize(hModule);
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

}  // extern "C"
#endif
