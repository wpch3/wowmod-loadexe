// RemoteAgent 的宿主侧实现（启动器这一边）。
// 目标进程里只跑 inject_first.hpp 描述的机器码，不加载任何模块。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "inject_first.hpp"

#include <tlhelp32.h>
#include <windows.h>

#include <cstring>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

bool write_proc(HANDLE p, uint64_t addr, const void* src, size_t n) {
  DWORD old = 0;
  if (!VirtualProtectEx(p, reinterpret_cast<void*>(addr), n, PAGE_EXECUTE_READWRITE, &old))
    return false;
  SIZE_T w = 0;
  return WriteProcessMemory(p, reinterpret_cast<void*>(addr), src, n, &w) && w == n;
}

bool read_proc(HANDLE p, uint64_t addr, void* dst, size_t n) {
  SIZE_T got = 0;
  return ReadProcessMemory(p, reinterpret_cast<const void*>(addr), dst, n, &got) && got == n;
}

// 取目标进程里某个模块的基址。
// 注意：这里用的是 Toolhelp 的模块快照，不是远程 GetModuleHandle ——
// 后者在我们自己的地址空间里查不到目标进程的模块。
uint64_t module_base_in(HANDLE process, const wchar_t* name) {
  uint64_t base = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                         GetProcessId(process));
  if (snap == INVALID_HANDLE_VALUE) return 0;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  if (Module32FirstW(snap, &me)) {
    do {
      if (_wcsicmp(me.szModule, name) == 0) {
        base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return base;
}

}  // namespace

bool RemoteAgent::attach(HANDLE process, std::string* err) {
  detach();
  if (!process) {
    if (err) *err = "进程句柄无效";
    return false;
  }
  process_ = process;

  // 1) 控制块：PAGE_READWRITE，代理和启动器都要读写
  const size_t ctl_size = kAgentCtlSize;
  void* ctl = VirtualAllocEx(process, nullptr, ctl_size, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
  if (!ctl) {
    if (err) *err = "分配控制块失败";
    return false;
  }
  ctl_va_ = reinterpret_cast<uint64_t>(ctl);

  // 2) 解析 kernel32!Sleep 在【目标进程】里的绝对地址：
  //    本进程 RVA + 目标进程 kernel32 基址（ASLR 下基址不同，RVA 相同）
  const HMODULE local_k32 = GetModuleHandleW(L"kernel32.dll");
  const uint64_t local_sleep = reinterpret_cast<uint64_t>(GetProcAddress(local_k32, "Sleep"));
  const uint64_t local_k32_base = reinterpret_cast<uint64_t>(local_k32);
  const uint64_t target_k32_base = module_base_in(process, L"kernel32.dll");
  uint64_t target_sleep = 0;
  if (local_sleep && local_k32_base && target_k32_base) {
    target_sleep = target_k32_base + (local_sleep - local_k32_base);
  }

  // 3) 控制块内容：magic + Sleep 指针
  std::vector<uint8_t> ctl_bytes(ctl_size, 0);
  const uint32_t magic = kAgentMagic;
  std::memcpy(ctl_bytes.data() + kOffMagic, &magic, 4);
  std::memcpy(ctl_bytes.data() + kOffSleepPtr, &target_sleep, 8);
  if (!write_proc(process, ctl_va_, ctl_bytes.data(), ctl_bytes.size())) {
    if (err) *err = "写入控制块失败";
    return false;
  }

  // 4) 代码块：PAGE_EXECUTE_READWRITE，没有 PE 头
  const std::vector<uint8_t> code = build_agent_code(ctl_va_);
  void* mem = VirtualAllocEx(process, nullptr, code.size(), MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!mem) {
    if (err) *err = "分配代码块失败";
    return false;
  }
  code_va_ = reinterpret_cast<uint64_t>(mem);
  if (!write_proc(process, code_va_, code.data(), code.size())) {
    if (err) *err = "写入代理代码失败";
    VirtualFreeEx(process, mem, 0, MEM_RELEASE);
    code_va_ = 0;
    return false;
  }
  FlushInstructionCache(process, mem, code.size());

  // 5) 从模块表查"代码块是否真的是私有内存"——私有内存不会出现在模块表里，
  //    这正是我们需要的（客户端扫描模块表时看不到它）。
  // 5b) 起线程。优先 CreateRemoteThread；失败则直接用 ntdll!NtCreateThreadEx
  //     （某些安全软件只 hook 前者）。
  HANDLE t = CreateRemoteThread(process, nullptr, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(code_va_), nullptr, 0,
                                nullptr);
  std::string thread_method = "CreateRemoteThread";
  if (!t) {
    const DWORD e1 = GetLastError();
    using NtCreateThreadExFn = LONG(WINAPI*)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID,
                                             LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
    // 在目标进程里取 ntdll 的基址（ASLR 下和本进程不同）
    const uint64_t local_ntdll =
        reinterpret_cast<uint64_t>(GetModuleHandleW(L"ntdll.dll"));
    const uint64_t local_fn =
        reinterpret_cast<uint64_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                 "NtCreateThreadEx"));
    const uint64_t target_ntdll = module_base_in(process, L"ntdll.dll");
    if (local_fn && local_ntdll && target_ntdll) {
      const uint64_t target_fn = target_ntdll + (local_fn - local_ntdll);
      // NtCreateThreadEx 是 native API，直接用 syscall 桩调用最稳：
      // 这里退一步，用我们自己进程里的函数指针，但把 process 句柄传进去 ——
      // 句柄是内核对象，跨进程有效，所以本进程的 ntdll 函数可以直接操作它。
      HANDLE th = nullptr;
      const LONG st = reinterpret_cast<NtCreateThreadExFn>(local_fn)(
          &th, THREAD_ALL_ACCESS, nullptr, process,
          reinterpret_cast<LPVOID>(code_va_), nullptr, 0, 0, 0, 0, nullptr);
      if (st == 0 && th) {
        t = th;
        thread_method = "NtCreateThreadEx";
      } else {
        if (err) *err = "CreateRemoteThread 失败(GetLastError=" + std::to_string(e1) +
                        ")，NtCreateThreadEx 也失败(NTSTATUS=0x" + to_hex(st, 8) +
                        ")，目标 ntdll=0x" + to_hex(target_ntdll, 16);
        return false;
      }
    } else {
      if (err) *err = "CreateRemoteThread 失败(GetLastError=" + std::to_string(e1) +
                      ")，且拿不到 ntdll 信息";
      return false;
    }
  }
  method_ = "远程代理（无模块, " + thread_method + "）";
  CloseHandle(t);  // 不需要等它，让它一直跑

  // 6) 确认代理活了：heartbeat 必须开始增长。
  //    如果心跳一直是 0，说明第一句指令都没执行 —— 那就去查线程状态：
  //      - 线程还在等（Suspended）-> CreateRemoteThread 被拦
  //      - 线程已退出 -> 退出码就是异常码（0xC0000005 等），能看到崩在哪
  AgentControl c;
  for (int i = 0; i < 40; ++i) {
    ::Sleep(50);
    if (!read_proc(process, ctl_va_, &c, sizeof(c))) continue;
    if (c.magic == kAgentMagic && c.heartbeat > 0) return true;
  }

  // 失败：把诊断信息拼出来
  std::string diag = "代理没有心跳。";
  uint64_t hb = 0, cmd = 0, st = 0;
  read_proc(process, ctl_va_ + kOffHeartbeat, &hb, 8);
  read_proc(process, ctl_va_ + kOffCommand, &cmd, 8);
  read_proc(process, ctl_va_ + kOffStatus, &st, 8);
  diag += "控制块: heartbeat=" + std::to_string(hb) + " command=" + std::to_string(cmd) +
          " status=" + std::to_string(st);
  uint64_t sleep_ptr = 0;
  read_proc(process, ctl_va_ + kOffSleepPtr, &sleep_ptr, 8);
  diag += ", Sleep=0x" + to_hex(sleep_ptr, 16);
  if (sleep_ptr == 0) diag += "（解析失败：kernel32 的 RVA 算错了）";

  // 枚举线程，找到起始地址等于我们代码块的线程
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap != INVALID_HANDLE_VALUE) {
    const DWORD pid = GetProcessId(process);
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
      do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE,
                               te.th32ThreadID);
        if (!th) continue;
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        // 判断这个线程是不是我们的代理：入口在 code_va_ 附近
        bool ours = false;
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(th, &ctx)) {
          // 代理线程此刻应该在我们的代码块里或 Sleep 里，退一步用 RIP 判断
          if (ctx.Rip >= code_va_ && ctx.Rip < code_va_ + 0x400) ours = true;
        }
        if (!ours && code != STILL_ACTIVE) {
          // 已退出的线程：退出码就是异常码
          if (code >= 0x80000000u) {
            diag += ", 有线程以异常码 0x" + to_hex(code, 8) + " 退出";
            ours = true;
          }
        }
        if (ours && code == STILL_ACTIVE) diag += ", 代理线程仍在运行(可能卡在循环里)";
        CloseHandle(th);
      } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
  }
  if (err) *err = diag;
  return false;
}

bool RemoteAgent::command(uint32_t cmd, uint64_t a0, uint64_t a1, uint64_t* r0, uint64_t* r1,
                          std::string* err, DWORD timeout_ms) {
  if (!process_ || !ctl_va_) {
    if (err) *err = "代理未附加";
    return false;
  }
  // 先清状态，再写参数，最后写命令（保证代理看到命令时参数已就绪）
  AgentControl c;
  if (!read_proc(process_, ctl_va_, &c, sizeof(c))) {
    if (err) *err = "读控制块失败";
    return false;
  }
  c.arg0 = a0;
  c.arg1 = a1;
  c.result0 = 0;
  c.result1 = 0;
  c.status = 0;
  // 只写回参数区，保留 magic/Sleep 指针
  struct Patch {
    uint64_t arg0, arg1, result0, result1;
    uint64_t status;
    uint32_t command;
  };
  if (!write_proc(process_, ctl_va_ + kOffArg0, &c.arg0, 8 * 4)) {
    if (err) *err = "写参数失败";
    return false;
  }
  if (!write_proc(process_, ctl_va_ + kOffStatus, &c.status, 8)) {
    if (err) *err = "写状态失败";
    return false;
  }
  if (!write_proc(process_, ctl_va_ + kOffCommand, &cmd, 4)) {
    if (err) *err = "写命令失败";
    return false;
  }

  // 等 status == 2
  const DWORD start = GetTickCount();
  while (GetTickCount() - start < timeout_ms) {
    ::Sleep(5);
    if (!read_proc(process_, ctl_va_, &c, sizeof(c))) continue;
    if (c.status == 2) {
      if (r0) *r0 = c.result0;
      if (r1) *r1 = c.result1;
      return true;
    }
    if (c.status == 3) {
      if (err) *err = "代理返回错误状态";
      return false;
    }
  }
  if (err) *err = "等待代理响应超时";
  return false;
}

bool RemoteAgent::call(uint64_t fn, uint64_t arg, uint64_t* ret, std::string* err) {
  uint64_t r0 = 0, r1 = 0;
  if (!command(kAgentCall, fn, arg, &r0, &r1, err)) return false;
  if (ret) *ret = r0;
  return true;
}

bool RemoteAgent::alive() const {
  if (!process_ || !ctl_va_) return false;
  AgentControl c;
  if (!read_proc(process_, ctl_va_, &c, sizeof(c))) return false;
  return c.magic == kAgentMagic && c.heartbeat > 0;
}

void RemoteAgent::detach() {
  if (process_ && ctl_va_) {
    // 让代理自己退出（写 quit 命令），然后回收内存
    uint32_t quit = kAgentQuit;
    write_proc(process_, ctl_va_ + kOffCommand, &quit, 4);
    ::Sleep(50);
  }
  if (process_) {
    if (code_va_) VirtualFreeEx(process_, reinterpret_cast<void*>(code_va_), 0, MEM_RELEASE);
    if (ctl_va_) VirtualFreeEx(process_, reinterpret_cast<void*>(ctl_va_), 0, MEM_RELEASE);
  }
  code_va_ = 0;
  ctl_va_ = 0;
  process_ = nullptr;
}

}  // namespace win
}  // namespace wowmod
#endif
