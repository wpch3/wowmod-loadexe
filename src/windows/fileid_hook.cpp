// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/fileid_hook.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "windows/runtime.hpp"

namespace wowmod {
namespace win {

namespace {

using VehHandler = LONG(NTAPI*)(PEXCEPTION_POINTERS);
using AddVehFn = PVOID(WINAPI*)(ULONG, VehHandler);

uint8_t* g_hook_addr = nullptr;
std::string g_id_register;
PVOID g_veh = nullptr;
HANDLE g_watcher = nullptr;
HANDLE g_stop = nullptr;
std::unordered_set<DWORD> g_applied_tids;

// id -> ANSI 路径字符串（进程生命周期内常驻，VEH 中只读不分配内存）
std::unordered_map<uint64_t, const std::string*> g_id_paths;

std::string utf8_to_acp(const std::string& s) {
  std::wstring w = utf8_to_wide(s);
  int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  if (n <= 0) return s;
  std::string out(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
  return out;
}

void build_path_table() {
  const auto& vfs = runtime().vfs;
  std::unordered_set<uint64_t> ids;
  for (const auto& h : vfs.effective_entries()) if (h.file_id) ids.insert(h.file_id);
  for (uint64_t id : ids) {
    auto hit = vfs.resolve_id(id);
    if (!hit || hit->blocked || hit->real_path.empty()) continue;
    g_id_paths[id] = new std::string(utf8_to_acp(to_native_path(hit->real_path)));
  }
  dlog("fileid hook: " + std::to_string(g_id_paths.size()) + " id->path entries");
}

#if defined(_WIN64)
uint64_t register_value(CONTEXT* c, const std::string& n) {
  if (n == "rax") return c->Rax;
  if (n == "rbx") return c->Rbx;
  if (n == "rcx") return c->Rcx;
  if (n == "rdx") return c->Rdx;
  if (n == "rsi") return c->Rsi;
  if (n == "rdi") return c->Rdi;
  if (n == "rbp") return c->Rbp;
  if (n == "r8") return c->R8;
  if (n == "r9") return c->R9;
  if (n == "r10") return c->R10;
  if (n == "r11") return c->R11;
  if (n == "r12") return c->R12;
  if (n == "r13") return c->R13;
  if (n == "r14") return c->R14;
  if (n == "r15") return c->R15;
  return 0;
}
#elif defined(_M_IX86) || defined(__i386__)
uint64_t register_value(CONTEXT* c, const std::string& n) {
  if (n == "eax" || n == "rax") return c->Eax;
  if (n == "ebx" || n == "rbx") return c->Ebx;
  if (n == "ecx" || n == "rcx") return c->Ecx;
  if (n == "edx" || n == "rdx") return c->Edx;
  if (n == "esi" || n == "rsi") return c->Esi;
  if (n == "edi" || n == "rdi") return c->Edi;
  if (n == "ebp" || n == "rbp") return c->Ebp;
  return 0;
}
#else
uint64_t register_value(CONTEXT*, const std::string&) { return 0; }
#endif

LONG NTAPI veh_handler(PEXCEPTION_POINTERS info) {
  if (!info || !info->ExceptionRecord || !info->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
  if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
  if (!g_hook_addr || info->ExceptionRecord->ExceptionAddress != g_hook_addr) return EXCEPTION_CONTINUE_SEARCH;
  CONTEXT* c = info->ContextRecord;
  uint64_t id = register_value(c, g_id_register);
  if (id) {
    auto it = g_id_paths.find(id);
    if (it != g_id_paths.end() && it->second && !it->second->empty()) {
#if defined(_WIN64)
      uint64_t ret_addr = 0;
      SIZE_T got = 0;
      if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(c->Rsp), &ret_addr,
                            sizeof(ret_addr), &got) && got == sizeof(ret_addr) && ret_addr) {
        c->Rax = reinterpret_cast<DWORD64>(it->second->c_str());
        c->Rip = ret_addr;
        c->Rsp += sizeof(uint64_t);
        c->EFlags |= 0x10000;  // RF: 跳过本次断点，直接执行返回地址
        return EXCEPTION_CONTINUE_EXECUTION;
      }
#elif defined(_M_IX86) || defined(__i386__)
      uint32_t ret_addr = 0;
      SIZE_T got = 0;
      if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(c->Esp), &ret_addr,
                            sizeof(ret_addr), &got) && got == sizeof(ret_addr) && ret_addr) {
        c->Eax = reinterpret_cast<DWORD>(it->second->c_str());
        c->Eip = ret_addr;
        c->Esp += sizeof(uint32_t);
        c->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
      }
#endif
    }
  }
  // 未命中：设置 Resume Flag，让断点处的原始指令正常执行（不重复触发）
#if defined(_WIN64) || defined(_M_IX86) || defined(__i386__)
  c->EFlags |= 0x10000;
#endif
  return EXCEPTION_CONTINUE_EXECUTION;
}

void apply_debug_registers() {
  if (!g_hook_addr) return;
  DWORD pid = GetCurrentProcessId();
  DWORD self_tid = GetCurrentThreadId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  THREADENTRY32 te;
  te.dwSize = sizeof(te);
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid || te.th32ThreadID == self_tid) continue;
      if (g_applied_tids.count(te.th32ThreadID)) continue;
      HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
      if (!t) continue;
      if (SuspendThread(t) != static_cast<DWORD>(-1)) {
        CONTEXT ctx;
        std::memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(t, &ctx)) {
          ctx.Dr0 = reinterpret_cast<DWORD64>(g_hook_addr);
          ctx.Dr7 |= 1;  // L0: 本地执行断点
#if defined(_WIN64)
          ctx.Dr7 &= ~static_cast<DWORD64>(0x000F0000);  // RW0/LEN0 = 执行/1字节
#else
          ctx.Dr7 &= ~static_cast<DWORD>(0x000F0000);
#endif
          if (SetThreadContext(t, &ctx)) g_applied_tids.insert(te.th32ThreadID);
        }
        ResumeThread(t);
      }
      CloseHandle(t);
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
}

DWORD WINAPI watcher(LPVOID) {
  while (WaitForSingleObject(g_stop, 200) == WAIT_TIMEOUT) apply_debug_registers();
  return 0;
}

}  // namespace

// 公共安装逻辑：给定模块名与 RVA，下硬件断点并接管为路径指针。
bool setup_hook(const std::string& module, uint32_t rva, const std::string& id_register,
                const std::string& label, std::string* err) {
  if (rva == 0) { if (err) *err = "hook 点 RVA 为 0"; return false; }
#if !(defined(_WIN64) || defined(_M_IX86) || defined(__i386__))
  if (err) *err = "硬件断点适配器目前仅支持 x86/x64 客户端";
  return false;
#else
  HMODULE base = nullptr;
  if (module.empty()) {
    base = GetModuleHandleW(nullptr);
  } else {
    std::wstring w = utf8_to_wide(module);
    base = GetModuleHandleW(w.c_str());
    if (!base) { if (err) *err = "无法取得模块基址: " + module; return false; }
  }
  if (!base) { if (err) *err = "无法取得客户端模块基址"; return false; }
  g_hook_addr = reinterpret_cast<uint8_t*>(base) + rva;
  g_id_register = to_lower(id_register.empty() ? "rdx" : id_register);

  build_path_table();
  if (g_id_paths.empty()) {
    if (err) *err = "没有任何 FileDataID 覆盖项，跳过 hook（仅需 VFS 层）";
    return false;
  }

  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  auto add_veh = reinterpret_cast<AddVehFn>(GetProcAddress(k32, "AddVectoredExceptionHandler"));
  if (!add_veh) { if (err) *err = "AddVectoredExceptionHandler 不可用"; return false; }
  if (!g_veh) g_veh = add_veh(1, veh_handler);
  if (!g_veh) { if (err) *err = "注册 VEH 失败"; return false; }

  if (!g_stop) g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  apply_debug_registers();
  if (g_stop && !g_watcher) g_watcher = CreateThread(nullptr, 0, watcher, nullptr, 0, nullptr);

  if (err) *err = "硬件断点已设在 0x" + to_hex(reinterpret_cast<uintptr_t>(g_hook_addr)) +
                  " (模块 " + (module.empty() ? "主 exe" : module) + ", rva 0x" + to_hex(rva) +
                  ", " + label + ", id=" + g_id_register + ")";
  dlog("fileid hook installed: " + *err);
  return true;
#endif
}

bool install_runtime_fileid_hook(const std::string& module, uint32_t rva,
                                 const std::string& pattern, const std::string& id_register,
                                 std::string* err) {
  return setup_hook(module, rva, id_register, "runtime:" + pattern.substr(0, 40), err);
}

bool install_fileid_hook(const HookPlan& plan, std::string* err) {
  if (plan.matches.empty()) {
    if (err) *err = "没有选中 hook 点";
    return false;
  }
  const HookMatch& m = plan.matches.front();
  if (m.rva == 0) {
    if (err) *err = "特征匹配位置不在 PE 节区内，无法确定内存地址";
    return false;
  }
  return setup_hook(m.module, m.rva, m.descriptor.id_register, m.descriptor.name, err);
}

}  // namespace win
}  // namespace wowmod
#endif
