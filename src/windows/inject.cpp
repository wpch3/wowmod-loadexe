// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/inject.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

std::string win_error_text(DWORD e) {
  switch (e) {
    case 0: return "（无错误）";
    case 2: return "ERROR_FILE_NOT_FOUND（找不到 DLL 文件）";
    case 3: return "ERROR_PATH_NOT_FOUND（路径不存在）";
    case 5: return "ERROR_ACCESS_DENIED（拒绝访问：Defender/ASR、完整性级别或受保护进程）";
    case 8: return "ERROR_NOT_ENOUGH_MEMORY";
    case 32: return "ERROR_SHARING_VIOLATION（文件被占用）";
    case 87: return "ERROR_INVALID_PARAMETER";
    case 126: return "ERROR_MOD_NOT_FOUND（DLL 或它的依赖，例如 UCRT 运行库，找不到）";
    case 127: return "ERROR_PROC_NOT_FOUND（缺少某个导出函数）";
    case 193: return "ERROR_BAD_EXE_FORMAT（位数不符或不是有效 PE）";
    case 216: return "ERROR_EXE_MACHINE_TYPE_MISMATCH（架构不匹配）";
    case 998: return "ERROR_NOACCESS（内存访问无效）";
    case 1114: return "ERROR_DLL_INIT_FAILED（DllMain 初始化失败/返回 FALSE）";
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
  size_t dir_off = magic == 0x10B ? opt + 96 : opt + 112;
  uint32_t imp_rva = u32(dir_off + 8);
  uint16_t nsec = u16(pe + 6), optsz = u16(pe + 20);
  std::vector<uint32_t> vas, ros, spans;
  size_t so = opt + optsz;
  for (uint16_t i = 0; i < nsec; ++i) {
    size_t o = so + 40 * static_cast<size_t>(i);
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

// 在【本进程】完整加载一次 DLL，用来区分「DLL 自身有问题」和「目标进程上下文有问题」。
// WOWMOD_PROBE 让 DllMain 不启动后台扫描线程，FreeLibrary 才安全。
std::string self_load_probe(const std::wstring& dll, DWORD* error_out) {
  SetEnvironmentVariableW(L"WOWMOD_PROBE", L"1");
  SetLastError(0);
  HMODULE h = LoadLibraryW(dll.c_str());
  DWORD e = GetLastError();
  if (h) FreeLibrary(h);
  SetEnvironmentVariableW(L"WOWMOD_PROBE", nullptr);
  if (error_out) *error_out = e;
  return h ? "本进程完整加载成功（DllMain + 依赖都正常）"
           : "本进程完整加载也失败 GetLastError=" + std::to_string(e) + " " + win_error_text(e);
}

// 远程调用块：把 LoadLibraryW 的 64 位返回值和目标进程里的 GetLastError
// 一起写回内存。只用数据页放结果，代码单独一页 RW -> RX，不用 RWX。
constexpr size_t kBlockSize = 0x400;   // 路径 + 结果区
constexpr size_t kResOff = 0x300;      // HMODULE (8)
constexpr size_t kErrOff = 0x308;      // DWORD (4)
constexpr size_t kCodeSize = 0x100;

void put8(std::vector<uint8_t>& v, uint64_t x) {
  for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}
void put32(std::vector<uint8_t>& v, uint32_t x) {
  for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}

// x64 thunk；rbx = lpParameter = 数据块基址
std::vector<uint8_t> build_thunk(uint64_t load_library, uint64_t rtl_get_last_error) {
  std::vector<uint8_t> c;
  auto op = [&](std::initializer_list<uint8_t> bytes) { for (uint8_t b : bytes) c.push_back(b); };
  op({0x53});                                  // push rbx
  op({0x48, 0x83, 0xEC, 0x30});              // sub rsp,30h (shadow space + align)
  op({0x48, 0x89, 0xCB});                     // mov rbx,rcx
  op({0x48, 0x8D, 0x8B}); put32(c, 0);       // lea rcx,[rbx+0]  -> wchar path
  op({0x48, 0xB8}); put8(c, load_library);    // mov rax,LoadLibraryW
  op({0xFF, 0xD0});                           // call rax
  op({0x48, 0x89, 0x83}); put32(c, static_cast<uint32_t>(kResOff));  // mov [rbx+res],rax
  op({0x48, 0xB8}); put8(c, rtl_get_last_error);  // mov rax,RtlGetLastWin32Error
  op({0xFF, 0xD0});                           // call rax
  op({0x89, 0x83}); put32(c, static_cast<uint32_t>(kErrOff));         // mov [rbx+err],eax
  op({0x48, 0x8B, 0x83}); put32(c, static_cast<uint32_t>(kResOff));  // mov rax,[rbx+res]
  op({0x48, 0x83, 0xC4, 0x30});              // add rsp,30h
  op({0x5B});                                 // pop rbx
  op({0xC3});                                 // ret
  return c;
}

bool write_mem(HANDLE p, void* dst, const void* src, size_t n) {
  SIZE_T w = 0;
  return WriteProcessMemory(p, dst, src, n, &w) && w == n;
}
bool read_mem(HANDLE p, const void* src, void* dst, size_t n) {
  SIZE_T r = 0;
  return ReadProcessMemory(p, src, dst, n, &r) && r == n;
}

struct ProbeResult {
  bool available = false;
  uint64_t module = 0;
  DWORD error = 0;
};

// 返回 true 表示远程调用机制本身可用（不代表加载成功）。
#if defined(_WIN64)
bool inject_with_probe(HANDLE process, const std::wstring& dll, uint64_t load_library,
                       uint64_t rtl_get_last_error, ProbeResult* out) {
  void* data = VirtualAllocEx(process, nullptr, kBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!data) return false;
  void* code = VirtualAllocEx(process, nullptr, kCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!code) { VirtualFreeEx(process, data, 0, MEM_RELEASE); return false; }

  std::vector<uint8_t> block(kBlockSize, 0);
  size_t path_bytes = (dll.size() + 1) * sizeof(wchar_t);
  if (path_bytes > kResOff) {  // 路径过长，退回简单注入
    VirtualFreeEx(process, code, 0, MEM_RELEASE);
    VirtualFreeEx(process, data, 0, MEM_RELEASE);
    return false;
  }
  std::memcpy(block.data(), dll.c_str(), path_bytes);
  auto thunk = build_thunk(load_library, rtl_get_last_error);
  if (!write_mem(process, data, block.data(), block.size()) ||
      !write_mem(process, code, thunk.data(), thunk.size())) {
    VirtualFreeEx(process, code, 0, MEM_RELEASE);
    VirtualFreeEx(process, data, 0, MEM_RELEASE);
    return false;
  }
  DWORD old_prot = 0;
  if (!VirtualProtectEx(process, code, kCodeSize, PAGE_EXECUTE_READ, &old_prot)) {
    VirtualFreeEx(process, code, 0, MEM_RELEASE);
    VirtualFreeEx(process, data, 0, MEM_RELEASE);
    return false;
  }

  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(code), data, 0, nullptr);
  if (!t) {
    VirtualFreeEx(process, code, 0, MEM_RELEASE);
    VirtualFreeEx(process, data, 0, MEM_RELEASE);
    return false;
  }
  DWORD wait = WaitForSingleObject(t, 20000);
  DWORD exit_code = 0;
  GetExitCodeThread(t, &exit_code);
  CloseHandle(t);
  if (wait == WAIT_TIMEOUT) {
    VirtualFreeEx(process, code, 0, MEM_RELEASE);
    VirtualFreeEx(process, data, 0, MEM_RELEASE);
    return false;
  }

  uint64_t mod = 0;
  DWORD err = 0;
  bool ok_read = read_mem(process, static_cast<uint8_t*>(data) + kResOff, &mod, 8) &&
                 read_mem(process, static_cast<uint8_t*>(data) + kErrOff, &err, 4);
  VirtualFreeEx(process, code, 0, MEM_RELEASE);
  VirtualFreeEx(process, data, 0, MEM_RELEASE);
  if (!ok_read) return false;
  out->available = true;
  out->module = mod;
  out->error = err;
  (void)exit_code;
  return true;
}
#else
bool inject_with_probe(HANDLE, const std::wstring&, uint64_t, uint64_t, ProbeResult*) { return false; }
#endif

uint64_t inject_simple(HANDLE process, const std::wstring& dll, void* load_library, std::string* err) {
  size_t bytes = (dll.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { if (err) *err = "VirtualAllocEx 失败 (" + std::to_string(GetLastError()) + ")"; return 0; }
  if (!write_mem(process, remote, dll.c_str(), bytes)) {
    if (err) *err = "WriteProcessMemory 失败 (" + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return 0;
  }
  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote, 0, nullptr);
  if (!t) {
    DWORD e = GetLastError();
    if (err) *err = "CreateRemoteThread 失败 (" + std::to_string(e) + ") " + win_error_text(e);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return 0;
  }
  DWORD wait = WaitForSingleObject(t, 20000);
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  if (wait == WAIT_TIMEOUT) { if (err) *err = "注入超时 20 秒"; return 0; }
  return code;
}

// 兜底：直接枚举目标进程模块，避免「32 位线程退出码」误判成功/失败。
bool module_loaded_in_process(HANDLE process, const std::wstring& dll) {
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

}  // namespace

bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err) {
  if (!process) { if (err) *err = "无效的进程句柄"; return false; }
  std::string local_path = normalize_path(wowmod::wide_to_utf8(dll_path));
  if (!file_exists(local_path)) { if (err) *err = "找不到注入模块: " + local_path; return false; }

  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  HMODULE ntd = GetModuleHandleW(L"ntdll.dll");
  if (!k32 || !ntd) { if (err) *err = "无法取得 kernel32/ntdll"; return false; }
  auto p_load = reinterpret_cast<uint64_t>(GetProcAddress(k32, "LoadLibraryW"));
  auto p_rtlerr = reinterpret_cast<uint64_t>(GetProcAddress(ntd, "RtlGetLastWin32Error"));
  if (!p_load) { if (err) *err = "无法解析 LoadLibraryW"; return false; }

  ProbeResult probe;
  uint64_t module = 0;
  bool used_probe = p_rtlerr && inject_with_probe(process, dll_path, p_load, p_rtlerr, &probe);
  if (used_probe) {
    module = probe.module;
  } else {
    std::string simple_err;
    module = inject_simple(process, dll_path, reinterpret_cast<void*>(p_load), &simple_err);
    if (err && !simple_err.empty()) *err = simple_err;
  }

  bool enumerated = false;
  if (module == 0) {
    // 远程线程退出码只有 32 位；直接查目标进程模块表更可靠。
    enumerated = module_loaded_in_process(process, dll_path);
  }
  if (module != 0 || enumerated) {
    if (err) {
      *err = enumerated ? "注入成功（已在目标进程模块表中确认 wowmod_hook.dll；远程线程退出码为 0 属于 32 位截断误判）"
                        : "注入成功，模块基址 0x" + to_hex(module, 16);
      if (used_probe && !enumerated) *err += "（目标进程 GetLastError=" + std::to_string(probe.error) + "）";
    }
    return true;
  }

  // ---- 失败：给出能定位问题的完整信息 ----
  std::vector<uint8_t> self_bytes;
  std::string read_err;
  read_binary_file(local_path, &self_bytes, &read_err);
  std::string deps = self_bytes.empty() ? "无法读取 DLL" : dependency_report(self_bytes);

  SetLastError(0);
  HMODULE mapped = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  DWORD map_err = GetLastError();
  std::string preflight = mapped ? "本地 PE 映射预检通过（x64/格式正确）"
                                 : "本地 PE 映射预检失败 GetLastError=" + std::to_string(map_err) + " " + win_error_text(map_err);
  if (mapped) FreeLibrary(mapped);

  DWORD self_err = 0;
  std::string self_probe = self_load_probe(dll_path, &self_err);

  std::string target_err;
  if (used_probe)
    target_err = "目标进程 GetLastError=" + std::to_string(probe.error) + " " + win_error_text(probe.error);
  else
    target_err = "远程调用诊断不可用（VirtualProtectEx/CreateRemoteThread 被拒绝），已退回简单注入";

  if (err) {
    *err = "LoadLibraryW 在目标进程返回 NULL。\n" +
           std::string("  ") + target_err + "\n" +
           "  " + preflight + "\n" +
           "  " + self_probe + "\n" +
           "  依赖: " + deps + "\n" +
           "  解读: 目标进程错误码若为 126/5/1114 见下表；若本进程能加载而目标进程不能，\n" +
           "        多半是挂起阶段 loader/UCRT 未就绪、Defender/ASR 拦截跨进程注入，或反注入保护。\n" +
           "  建议: ① 以管理员运行 PowerShell ② 把文件移到 D:\\wowmod\\ 并加 Defender 排除项\n" +
           "        ③ 装 VC++ 2015–2022 x64 运行库 ④ 跑 .\\scripts\\diagnose-load.ps1 对照。";
  }
  return false;
}

}  // namespace win
}  // namespace wowmod
#endif
