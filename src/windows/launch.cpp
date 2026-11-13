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
  std::string inject_err;
  bool injected = win::inject_dll(pi.hProcess, dll_w, &inject_err);
  bool resumed = false;
  // 部分加壳客户端在 CREATE_SUSPENDED 阶段 loader / UCRT 还没初始化完，
  // LoadLibraryW 会返回 NULL。回退：先恢复主线程，等一小会儿再注入一次。
  if (!injected && cfg.hooks.inject_retry) {
    std::string first_err = inject_err;
    ResumeThread(pi.hThread);
    resumed = true;
    int attempts = std::max(1, std::min(10, cfg.hooks.inject_retry_attempts));
    int base = std::max(0, std::min(10000, cfg.hooks.inject_retry_delay_ms));
    std::string all_retries;
    for (int i = 1; i <= attempts && !injected; ++i) {
      Sleep(static_cast<DWORD>(static_cast<long long>(base) * i));
      std::string retry_err;
      if (win::inject_dll(pi.hProcess, dll_w, &retry_err)) {
        injected = true;
        inject_err = "挂起阶段注入失败，已在进程初始化后第 " + std::to_string(i) +
                     " 次重试成功；" + retry_err + "\n  首次失败: " + first_err;
      } else {
        all_retries += "\n  第 " + std::to_string(i) + " 次重试: " + retry_err;
      }
    }
    if (!injected) inject_err = "挂起阶段注入失败: " + first_err + all_retries;
  }
  if (injected) {
    if (!resumed) ResumeThread(pi.hThread);
  } else {
    TerminateProcess(pi.hProcess, 1);  // 不注入就不要启动，避免无覆盖层运行
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
