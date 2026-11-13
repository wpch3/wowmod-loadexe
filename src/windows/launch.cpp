// Windows 启动器：CREATE_SUSPENDED -> 注入覆盖层 -> 恢复主线程。
// SPDX-License-Identifier: MIT
#ifndef _WIN32
#include "platform/launch.hpp"
namespace wowmod {
LaunchResult launch_game(const Config&, const ClientInfo&, const Vfs&, const HookPlan&, const Diagnostics&, bool) {
  LaunchResult r; r.code = 1; r.message = "需要 Windows"; return r;
}
}  // namespace wowmod
#else

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include "platform/launch.hpp"
#include "windows/inject.hpp"
#include "wowmod/util.hpp"
#include "wowmod/version.hpp"

namespace fs = std::filesystem;
namespace wowmod {

namespace {

std::wstring quote_cmdline(const std::string& exe) {
  return L"\"" + utf8_to_wide(to_native_path(exe)) + L"\"";
}

std::string find_hook_dll() {
  std::vector<std::string> candidates = {
      join_path(exe_dir_path(), "wowmod_hook.dll"),
      join_path(absolute_path("."), "wowmod_hook.dll"),
  };
  for (const auto& p : candidates) if (file_exists(p)) return p;
  return "";
}

}  // namespace

LaunchResult launch_game(const Config& cfg, const ClientInfo& ci, const Vfs& vfs,
                         const HookPlan& hooks, const Diagnostics& diag, bool dry_run) {
  LaunchResult r;
  if (dry_run) { r.message = "干跑完成（未启动客户端）"; return r; }

  std::string exe = cfg.client.exe;
  if (exe.empty() || !file_exists(exe)) {
    std::string root = cfg.client.game_dir.empty() ? absolute_path(".") : cfg.client.game_dir;
    auto exes = discover_client_exes(root);
    if (!exes.empty()) exe = exes.front();
  }
  if (exe.empty() || !file_exists(exe)) {
    r.code = 1;
    r.message = "找不到客户端 exe。请在配置的 client.exe 中指定，或运行 wowmod init 生成示例配置。";
    return r;
  }

  // 位数检查（不是版本检查：任何 build 都可以，只有位数必须匹配）
#ifdef _WIN64
  const std::string loader_arch = "x64";
#else
  const std::string loader_arch = "x86";
#endif
  ClientInfo ci2 = ci;
  std::vector<uint8_t> bytes;
  if (read_binary_file(exe, &bytes, nullptr)) {
    ClientInfo pe;
    std::string perr;
    if (parse_pe_metadata(bytes, &pe, &perr)) ci2.arch = pe.arch;
  }
  if (!ci2.arch.empty() && ci2.arch != "unknown" && ci2.arch != loader_arch && !starts_with(ci2.arch, "unknown")) {
    r.code = 1;
    r.message = "架构不匹配: 客户端是 " + ci2.arch + "，当前加载器是 " + loader_arch +
                "。请用对应位数重新构建（这不是版本限制）。";
    return r;
  }

  std::string dll = find_hook_dll();
  if (dll.empty()) {
    r.code = 1;
    r.message = "找不到 wowmod_hook.dll（应与 wowmod.exe 放在同一目录）。请先构建 Windows 版本。";
    return r;
  }

  if (!cfg.hooks.allow_fallback && hooks.mode != "fileid") {
    r.code = 1;
    r.message = "配置了 hooks.allowFallback=false，但当前客户端没有可用的 FileDataID hook 点: " + hooks.reason +
                "\n可添加一条针对该客户端的特征，或改为 true 使用通用 VFS 模式。";
    return r;
  }

  if (cfg.client.clear_cache) {
    std::error_code ec;
    fs::remove_all(fs::path(to_native_path(join_path(cfg.client.game_dir, "Cache"))), ec);
  }

  // 环境变量由子进程继承，注入 DLL 从中读取配置路径
  if (!cfg.path.empty()) SetEnvironmentVariableW(L"WOWMOD_CONFIG", utf8_to_wide(to_native_path(cfg.path)).c_str());

  std::wstring cmd = quote_cmdline(exe);
  for (const auto& a : cfg.client.args) cmd += L" " + utf8_to_wide(a);
  std::wstring workdir = utf8_to_wide(to_native_path(parent_path(exe)));

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
  cmd_buf.push_back(L'\0');

  BOOL ok = CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, FALSE,
                           CREATE_SUSPENDED, nullptr, workdir.c_str(), &si, &pi);
  if (!ok) {
    // 某些客户端要求以 lpApplicationName 方式启动
    ok = CreateProcessW(utf8_to_wide(to_native_path(exe)).c_str(), cmd_buf.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, workdir.empty() ? nullptr : workdir.c_str(), &si, &pi);
  }
  if (!ok) {
    r.code = 1;
    r.message = "CreateProcess 失败 (" + std::to_string(GetLastError()) + ")";
    return r;
  }

  std::wstring dll_w = utf8_to_wide(to_native_path(dll));
  std::vector<std::string> methods = cfg.hooks.inject_methods;
  if (methods.empty()) methods = {"loadlibrary", "ntcreatethreadex"};

  // 机制 4：SetWindowsHookEx(WH_GETMESSAGE)。user32 会在客户端 GUI 线程收消息时
  // 自动把本 DLL 加载进那个进程，完全不经过 CreateRemoteThread / 远程 LoadLibraryW。
  // 有些客户端的加载层会静默拒绝远程加载，但对系统自身注入的 DLL 放行。
  HMODULE self_dll = nullptr;
  HHOOK win_hook = nullptr;
  std::string hook_note;
  if (cfg.hooks.inject_windows_hook) {
    SetEnvironmentVariableW(L"WOWMOD_PROBE", L"1");
    self_dll = LoadLibraryW(dll_w.c_str());
    SetEnvironmentVariableW(L"WOWMOD_PROBE", nullptr);
    if (!self_dll) {
      hook_note = "SetWindowsHookEx 机制不可用：本进程 LoadLibraryW 失败 (" +
                  std::to_string(GetLastError()) + ")";
    } else {
      auto proc = reinterpret_cast<HOOKPROC>(GetProcAddress(self_dll, "wowmod_hook_proc"));
      if (!proc) hook_note = "SetWindowsHookEx 机制不可用：缺少导出 wowmod_hook_proc";
      else {
        win_hook = SetWindowsHookExW(WH_GETMESSAGE, proc, self_dll, pi.dwThreadId);
        hook_note = win_hook ? "WH_GETMESSAGE 钩子已挂到客户端主线程 " + std::to_string(pi.dwThreadId)
                             : "SetWindowsHookExW 失败 (" + std::to_string(GetLastError()) + ")";
      }
    }
  }

  auto render = [](const win::InjectReport& rp) {
    std::string out;
    for (const auto& a : rp.attempts) out += "\n  " + a;
    return out;
  };
  auto poll_hook = [&](int ms) {
    for (int k = 0; k < ms / 100; ++k) {
      if (win::is_module_loaded(pi.hProcess, dll_w)) return true;
      Sleep(100);
    }
    return false;
  };

  bool injected = false, resumed = false;
  std::string inject_err;
  win::InjectReport first = win::inject_dll(pi.hProcess, pi.hThread, false, dll_w, methods);
  injected = first.success;
  inject_err = injected ? "注入成功（" + first.method + "）" : "挂起阶段:" + render(first);
  if (!hook_note.empty()) inject_err += "\n  " + hook_note;

  if (!injected && cfg.hooks.inject_retry) {
    std::string first_err = inject_err;
    ResumeThread(pi.hThread);
    resumed = true;
    int attempts = std::max(1, std::min(10, cfg.hooks.inject_retry_attempts));
    int base = std::max(0, std::min(10000, cfg.hooks.inject_retry_delay_ms));
    std::string all;
    for (int i = 1; i <= attempts && !injected; ++i) {
      Sleep(static_cast<DWORD>(static_cast<long long>(base) * i));
      if (win_hook && poll_hook(1500)) {
        injected = true;
        inject_err = "Windows 钩子注入成功（user32 已把 wowmod_hook.dll 加载进客户端）\n  " + hook_note +
                     "\n  首次失败:" + first_err;
        break;
      }
      std::vector<std::string> m2 = methods;
      if (std::find(m2.begin(), m2.end(), "apc") == m2.end()) m2.push_back("apc");
      win::InjectReport rp = win::inject_dll(pi.hProcess, pi.hThread, true, dll_w, m2);
      if (rp.success) {
        injected = true;
        inject_err = "第 " + std::to_string(i) + " 次重试注入成功（" + rp.method + "）\n  首次失败:" + first_err;
      } else {
        all += "\n  第 " + std::to_string(i) + " 次重试:" + render(rp);
      }
    }
    if (!injected) inject_err = "挂起阶段:" + first_err + all;
  }
  if (injected) {
    if (!resumed) ResumeThread(pi.hThread);
  } else {
    TerminateProcess(pi.hProcess, 1);  // 不注入就不要启动，避免无覆盖层运行
    if (win_hook) UnhookWindowsHookEx(win_hook);
    if (self_dll) FreeLibrary(self_dll);
  }

  // Windows 钩子由本进程持有：必须等客户端退出，否则钩子销毁后 DLL 可能被卸载。
  bool keep_alive = injected && win_hook != nullptr;
  if (keep_alive) {
    WaitForSingleObject(pi.hProcess, INFINITE);
    UnhookWindowsHookEx(win_hook);
    if (self_dll) FreeLibrary(self_dll);
  }

  r.pid = pi.dwProcessId;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  if (!injected) {
    r.code = 1;
    r.message = "注入失败，已终止客户端: " + inject_err;
    return r;
  }

  std::ostringstream os;
  os << "已启动客户端 PID " << r.pid << "\n"
     << "  版本: " << ci.version_string << " (build " << ci.build << ") — 无版本白名单\n"
     << "  覆盖层: " << vfs.effective_entries().size() << " 条 (" << vfs.stats().generated << " 个内存生成文件)\n"
     << "  hook 模式: " << hooks.mode << " — " << hooks.reason << "\n"
     << "  " << inject_err << "\n"
     << "  配置: " << cfg.path;
  if (!diag.items().empty()) os << "\n  诊断: " << diag.count(Level::Warn) << " 警告, " << diag.count(Level::Error) << " 错误";
  r.message = os.str();
  return r;
}

}  // namespace wowmod
#endif
