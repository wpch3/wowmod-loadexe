// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/inject.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

std::string win_error_text(DWORD e) {
  switch (e) {
    case 0: return "（没有捕获到 Win32 错误；单凭 0 无法判断失败原因）";
    case 2: return "ERROR_FILE_NOT_FOUND";
    case 3: return "ERROR_PATH_NOT_FOUND";
    case 5: return "ERROR_ACCESS_DENIED（Defender/ASR/完整性级别/受保护进程）";
    case 126: return "ERROR_MOD_NOT_FOUND（依赖缺失，例如 UCRT 运行库）";
    case 127: return "ERROR_PROC_NOT_FOUND";
    case 193: return "ERROR_BAD_EXE_FORMAT（位数不符）";
    case 216: return "ERROR_EXE_MACHINE_TYPE_MISMATCH";
    case 998: return "ERROR_NOACCESS";
    case 1114: return "ERROR_DLL_INIT_FAILED（DllMain 失败）";
    default: return "";
  }
}

std::string dependency_report(const std::vector<uint8_t>& b) {
  auto u16 = [&](size_t o) -> uint16_t {
    return o + 2 > b.size() ? 0 : static_cast<uint16_t>(b[o] | (b[o + 1] << 8));
  };
  auto u32 = [&](size_t o) -> uint32_t {
    return o + 4 > b.size() ? 0 : static_cast<uint32_t>(b[o]) | (static_cast<uint32_t>(b[o + 1]) << 8) |
                                       (static_cast<uint32_t>(b[o + 2]) << 16) | (static_cast<uint32_t>(b[o + 3]) << 24);
  };
  size_t pe = b.size() > 0x40 ? u32(0x3C) : 0;
  if (!pe || u32(pe) != 0x00004550u) return "无法解析 PE 头";
  size_t opt = pe + 24;
  uint16_t magic = u16(opt);
  uint32_t imp_rva = u32((magic == 0x10B ? opt + 96 : opt + 112) + 8);
  uint16_t nsec = u16(pe + 6), optsz = u16(pe + 20);
  std::vector<uint32_t> vas, ros, spans;
  for (uint16_t i = 0; i < nsec; ++i) {
    size_t o = opt + optsz + 40 * static_cast<size_t>(i);
    uint32_t vs = u32(o + 8), va = u32(o + 12), rs = u32(o + 16), ro = u32(o + 20);
    vas.push_back(va); ros.push_back(ro); spans.push_back(std::max(vs, rs));
  }
  auto r2o = [&](uint32_t rva) -> size_t {
    for (size_t i = 0; i < vas.size(); ++i)
      if (rva >= vas[i] && rva - vas[i] < spans[i]) return ros[i] + (rva - vas[i]);
    return rva < b.size() && (vas.empty() || rva < vas[0]) ? rva : static_cast<size_t>(-1);
  };
  size_t io = r2o(imp_rva);
  if (io == static_cast<size_t>(-1)) return "无导入表";
  std::vector<std::string> deps;
  for (size_t o = io; o + 20 <= b.size(); o += 20) {
    uint32_t name_rva = u32(o + 12);
    if (!name_rva) break;
    size_t no = r2o(name_rva);
    if (no == static_cast<size_t>(-1) || no >= b.size()) continue;
    std::string name;
    for (size_t p = no; p < b.size() && b[p] && name.size() < 128; ++p) name.push_back(static_cast<char>(b[p]));
    if (name.empty()) continue;
    std::string lower = to_lower(name);
    if (starts_with(lower, "api-ms-") || starts_with(lower, "ext-ms-")) continue;
    if (std::find(deps.begin(), deps.end(), name) == deps.end()) deps.push_back(name);
  }
  if (deps.empty()) return "仅依赖系统 API Set（UCRT / KERNEL32）";
  std::string out;
  for (const auto& d : deps) {
    std::wstring w = utf8_to_wide(d);
    bool ok = GetModuleHandleW(w.c_str()) != nullptr;
    if (!ok) {
      HMODULE h = LoadLibraryExW(w.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
      ok = h != nullptr;
      if (h) FreeLibrary(h);
    }
    out += (ok ? "[OK] " : "[缺失] ") + d + "  ";
  }
  return out;
}

// 唯一的成功判据：目标进程的模块表里是否出现 wowmod_hook.dll。
bool module_loaded(HANDLE process, const std::wstring& dll) {
  DWORD pid = GetProcessId(process);
  if (!pid) return false;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE) return false;
  std::wstring name = dll;
  size_t cut = name.find_last_of(L"\\/");
  if (cut != std::wstring::npos) name = name.substr(cut + 1);
  for (auto& ch : name) if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(snap, &me)) {
    do {
      std::wstring m = me.szModule;
      for (auto& ch : m) if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
      if (m == name) { found = true; break; }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
}

bool write_mem(HANDLE p, void* dst, const void* src, size_t n) {
  SIZE_T w = 0;
  return WriteProcessMemory(p, dst, src, n, &w) && w == n;
}

std::string local_error(DWORD e) { return std::to_string(e) + " " + win_error_text(e); }

// ---- 机制 1：经典 CreateRemoteThread(LoadLibraryW) ----
std::string try_remote_thread(HANDLE process, void* remote, void* load_library) {
  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote, 0, nullptr);
  if (!t) return "CreateRemoteThread 失败 " + local_error(GetLastError());
  DWORD wait = WaitForSingleObject(t, 15000);
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  if (wait == WAIT_TIMEOUT) return "远程线程 15 秒未结束（进程可能仍挂起）";
  return "远程线程退出码 0x" + to_hex(code, 8) +
         (code == 0 ? "（LoadLibraryW 返回 NULL）" : "");
}

// ---- 机制 2：NtCreateThreadEx（ntdll，绕过 kernel32 层 hook） ----
using NtCreateThreadExFn = HRESULT(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
                                           ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
std::string try_nt_create_thread(HANDLE process, void* remote, void* load_library, HMODULE ntd) {
  auto fn = reinterpret_cast<NtCreateThreadExFn>(GetProcAddress(ntd, "NtCreateThreadEx"));
  if (!fn) return "NtCreateThreadEx 不可用（系统版本较旧）";
  HANDLE t = nullptr;
  HRESULT hr = fn(&t, 0x1FFFFF /* THREAD_ALL_ACCESS */, nullptr, process,
                  load_library, remote, 0 /* 无隐藏 flag */, 0, 0, 0, nullptr);
  if (FAILED(hr) || !t) return "NtCreateThreadEx 失败 HRESULT=0x" + to_hex(static_cast<uint32_t>(hr), 8);
  DWORD wait = WaitForSingleObject(t, 15000);
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  if (wait == WAIT_TIMEOUT) return "NtCreateThreadEx 线程 15 秒未结束";
  return "NtCreateThreadEx 退出码 0x" + to_hex(code, 8);
}

// ---- 机制 3：QueueUserAPC 到主线程（不创建新线程；部分保护只拦远程线程） ----
std::string try_apc(HANDLE process, HANDLE main_thread, void* remote, void* load_library,
                    const std::wstring& dll) {
  if (!main_thread) return "没有主线程句柄，跳过 APC";
  if (!QueueUserAPC(reinterpret_cast<PAPCFUNC>(load_library), main_thread,
                    reinterpret_cast<ULONG_PTR>(remote))) {
    return "QueueUserAPC 失败 " + local_error(GetLastError());
  }
  // APC 只在线程进入 alertable wait 时执行；轮询模块表最多 3 秒。
  for (int i = 0; i < 30; ++i) {
    if (module_loaded(process, dll)) return "APC 已触发，模块表确认加载成功";
    Sleep(100);
  }
  return "APC 已排队但 3 秒内未进入 alertable wait（客户端未调用可等待 API）";
}

}  // namespace

bool is_module_loaded(HANDLE process, const std::wstring& dll) { return module_loaded(process, dll); }

InjectReport inject_dll(HANDLE process, HANDLE main_thread, bool allow_apc,
                        const std::wstring& dll_path, const std::vector<std::string>& methods) {
  InjectReport rep;
  std::string local_path = normalize_path(wowmod::wide_to_utf8(dll_path));
  if (!process) { rep.attempts.push_back("无效的进程句柄"); return rep; }
  if (!file_exists(local_path)) { rep.attempts.push_back("找不到注入模块: " + local_path); return rep; }

  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  HMODULE ntd = GetModuleHandleW(L"ntdll.dll");
  if (!k32) { rep.attempts.push_back("无法取得 kernel32"); return rep; }
  auto p_load = reinterpret_cast<void*>(GetProcAddress(k32, "LoadLibraryW"));
  if (!p_load) { rep.attempts.push_back("无法解析 LoadLibraryW"); return rep; }

  // 路径内存保持到整个尝试序列结束（APC 可能异步使用）。
  size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { rep.attempts.push_back("VirtualAllocEx 失败 " + local_error(GetLastError())); return rep; }
  if (!write_mem(process, remote, dll_path.c_str(), bytes)) {
    rep.attempts.push_back("WriteProcessMemory 失败 " + local_error(GetLastError()));
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return rep;
  }

  std::vector<std::string> ms = methods;
  if (ms.empty()) ms = {"loadlibrary", "ntcreatethreadex", "apc"};
  for (const auto& m : ms) {
    if (module_loaded(process, dll_path)) {  // 上一次尝试可能异步成功了
      rep.success = true; rep.method = m + "（前一次尝试已生效）";
      break;
    }
    std::string result;
    std::string name = to_lower(m);
    if (name == "loadlibrary") result = try_remote_thread(process, remote, p_load);
    else if (name == "ntcreatethreadex") result = try_nt_create_thread(process, remote, p_load, ntd);
    else if (name == "windowshook") { rep.attempts.push_back("windowshook: 由启动器单独处理"); continue; }
    else if (name == "apc") {
      if (!allow_apc) { rep.attempts.push_back("apc: 挂起阶段跳过"); continue; }
      result = try_apc(process, main_thread, remote, p_load, dll_path);
    } else { rep.attempts.push_back(m + ": 未知注入方式"); continue; }

    // 关键：用模块表判定，而不是线程退出码。
    bool loaded = module_loaded(process, dll_path);
    rep.attempts.push_back(m + ": " + result + (loaded ? " -> 模块表确认已加载" : " -> 模块表未出现"));
    if (loaded) { rep.success = true; rep.method = m; break; }
  }

  VirtualFreeEx(process, remote, 0, MEM_RELEASE);

  if (!rep.success) {
    std::vector<uint8_t> self_bytes;
    std::string read_err;
    read_binary_file(local_path, &self_bytes, &read_err);
    SetLastError(0);
    HMODULE mapped = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    DWORD map_err = GetLastError();
    if (mapped) FreeLibrary(mapped);
    SetEnvironmentVariableW(L"WOWMOD_PROBE", L"1");
    SetLastError(0);
    HMODULE self = LoadLibraryW(dll_path.c_str());
    DWORD self_err = GetLastError();
    if (self) FreeLibrary(self);
    SetEnvironmentVariableW(L"WOWMOD_PROBE", nullptr);

    rep.attempts.push_back("本地 PE 映射预检: " + std::string(mapped ? "通过 (x64/格式正确)" : "失败 GetLastError=" + local_error(map_err)));
    rep.attempts.push_back("本进程 LoadLibrary 探测: " + std::string(self ? "成功（WOWMOD_PROBE 模式，跳过 overlay 初始化）" : "失败 GetLastError=" + local_error(self_err)));
    rep.attempts.push_back("依赖: " + (self_bytes.empty() ? "无法读取 DLL" : dependency_report(self_bytes)));
    rep.attempts.push_back("结论: 这些注入尝试没有在目标进程模块表中确认 DLL；当前结果不足以区分初始化时序、"
                           "目标进程状态、线程创建限制或客户端加载策略。请勿据此断言已找到反注入原因。");
  }
  return rep;
}

bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err) {
  InjectReport r = inject_dll(process, nullptr, false, dll_path, {});
  if (err) {
    *err = r.success ? "注入成功（" + r.method + "）" : "注入失败（所有机制）";
    for (const auto& a : r.attempts) *err += "\n  " + a;
  }
  return r.success;
}

}  // namespace win
}  // namespace wowmod
#endif
