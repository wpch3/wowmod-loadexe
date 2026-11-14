// 远程代理机器码生成器。
//
// 这段代码在目标进程里以独立线程运行，没有 PE 头、不在模块表里，
// 因此不会触发客户端的 0x1100 模块扫描。
//
// 指令流（全程只用绝对地址，位置无关）：
//   loop:
//     rax = [ctl+8]        ; command
//     if rax == 0: goto idle
//     if rax == 9: goto quit
//     if rax == 2: call arg0 with arg1 in rcx   -> result0
//     else: result0 = command (回声，用于 ping)
//     [ctl+40] = result0
//     [ctl+24] = 2         ; status = 完成
//     [ctl+8]  = 0         ; 清命令
//   idle:
//     [ctl+48] += 1        ; heartbeat
//     Sleep(1)             ; 通过 kernel32!Sleep，避免空转吃满 CPU
//     goto loop
//   quit:
//     [ctl+24] = 3
//     ret
//
// 注意：Sleep 的地址由调用方传入（启动器在本进程里解析 kernel32!Sleep 的
// RVA，再加上目标进程 kernel32 的基址）。这样代理不需要自己解析任何导入表。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include <cstring>

#include "inject_first.hpp"

namespace wowmod {
namespace win {

namespace {
struct Emitter {
  std::vector<uint8_t> c;
  void db(std::initializer_list<uint8_t> bs) { c.insert(c.end(), bs.begin(), bs.end()); }
  void dq(uint64_t v) {
    const size_t at = c.size();
    c.resize(at + 8);
    std::memcpy(c.data() + at, &v, 8);
  }
  // 记录需要回填的"循环起点"等
  size_t mark() const { return c.size(); }
};

// ctl 字段偏移直接取自 static_assert 锁定的 offsetof，绝不手写。
using namespace wowmod::win;
constexpr int32_t kCommand = static_cast<int32_t>(kOffCommand);
constexpr int32_t kArg0 = static_cast<int32_t>(kOffArg0);
constexpr int32_t kArg1 = static_cast<int32_t>(kOffArg1);
constexpr int32_t kResult0 = static_cast<int32_t>(kOffResult0);
constexpr int32_t kStatus = static_cast<int32_t>(kOffStatus);
constexpr int32_t kHeartbeat = static_cast<int32_t>(kOffHeartbeat);
constexpr int32_t kSleepPtr = static_cast<int32_t>(kOffSleepPtr);
}  // namespace

std::vector<uint8_t> build_agent_code(uint64_t ctl_va) {
  Emitter e;
  // 【第一件事】把 heartbeat 置 1。
  // 如果启动器看到 0，说明我们的第一句指令就没跑 —— 问题在
  // CreateRemoteThread（被拦/没调度）而不是后面的代码。
  e.db({0x48, 0xB9}); e.dq(ctl_va + kHeartbeat);  // mov rcx, &heartbeat
  e.db({0x48, 0xC7, 0x01, 0x01, 0x00, 0x00, 0x00});  // mov qword [rcx], 1
  // 保存所有要用的寄存器（这个线程是我们自己的，但保持整洁便于调试）
  e.db({0x50});              // push rax
  e.db({0x51});              // push rcx
  e.db({0x52});              // push rdx
  e.db({0x41, 0x50});        // push r8
  e.db({0x41, 0x51});        // push r9
  // 栈对齐推导（Windows x64 要求 call 时 rsp%16==0）：
  //   新建线程 rsp % 16 == 0
  //   5 次 push（每个 8 字节）-> rsp % 16 == 8
  //   再 sub 8             -> rsp % 16 == 0  ✅ 这时 call 才合法
  // 之前写成 0x28（40 字节）会让 rsp%16==0+8，每次 call 都错位，
  // 内部一碰 SSE 指令就崩 —— 这正是"没有心跳"的原因之一。
  e.db({0x48, 0x83, 0xEC, 0x08});  // sub rsp, 8

  const size_t loop = e.mark();
  // rax = [ctl+8]
  e.db({0x48, 0xB9}); e.dq(ctl_va + kCommand);   // mov rcx, &command
  e.db({0x48, 0x8B, 0x01});                       // mov rax, [rcx]
  // if command == 0 -> idle
  e.db({0x48, 0x85, 0xC0});                       // test rax, rax
  e.db({0x0F, 0x84, 0x00, 0x00, 0x00, 0x00});     // je idle       (回填)
  const size_t je_idle_at = e.c.size() - 4;       // disp32 起始位置
  // if command == 9 -> quit
  e.db({0x48, 0x83, 0xF8, 0x09});                 // cmp rax, 9
  e.db({0x0F, 0x84, 0x00, 0x00, 0x00, 0x00});     // je quit       (回填)
  const size_t je_quit_at = e.c.size() - 4;

  // if command == 2 -> call arg0(arg1)
  e.db({0x48, 0x83, 0xF8, 0x02});                 // cmp rax, 2
  e.db({0x75, 0x00});                             // jne skip_call (回填 rel8)
  const size_t jne_disp_at = e.c.size() - 1;
  e.db({0x48, 0xB9}); e.dq(ctl_va + kArg1);       // mov rcx, &arg1
  e.db({0x48, 0x8B, 0x09});                       // mov rcx, [rcx]   -> 参数
  e.db({0x48, 0xBA}); e.dq(ctl_va + kArg0);       // mov rdx, &arg0
  e.db({0x48, 0x8B, 0x02});                       // mov rax, [rdx]   -> 函数地址
  e.db({0xFF, 0xD0});                             // call rax
  e.db({0x48, 0xBA}); e.dq(ctl_va + kResult0);    // mov rdx, &result0
  e.db({0x48, 0x89, 0x02});                       // mov [rdx], rax
  const size_t skip_call = e.mark();

  // 统一写回：status = 2, command = 0
  e.db({0x48, 0xB9}); e.dq(ctl_va + kStatus);     // mov rcx, &status
  e.db({0x48, 0xC7, 0x01, 0x02, 0x00, 0x00, 0x00});  // mov qword [rcx], 2
  e.db({0x48, 0xB9}); e.dq(ctl_va + kCommand);    // mov rcx, &command
  e.db({0x48, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00});  // mov qword [rcx], 0

  // idle:
  const size_t idle = e.mark();
  e.db({0x48, 0xB9}); e.dq(ctl_va + kHeartbeat);  // mov rcx, &heartbeat
  e.db({0x48, 0xFF, 0x01});                       // inc qword [rcx]
  // Sleep(1) —— 由调用方保证 [ctl+64] 存着 Sleep 的绝对地址
  e.db({0x48, 0xBA}); e.dq(ctl_va + kSleepPtr);   // mov rdx, &sleep_ptr
  e.db({0x48, 0x8B, 0x02});                       // mov rax, [rdx]
  e.db({0x48, 0x85, 0xC0});                       // test rax, rax
  e.db({0x74, 0x00});                             // je  skip_sleep (回填 rel8)
  const size_t je_sleep_disp_at = e.c.size() - 1;
  e.db({0xB9, 0x01, 0x00, 0x00, 0x00});           // mov ecx, 1
  e.db({0xFF, 0xD0});                             // call rax
  const size_t skip_sleep = e.mark();
  // 回到 loop
  e.db({0xE9, 0x00, 0x00, 0x00, 0x00});           // jmp loop (回填)
  const size_t jmp_loop_at = e.c.size() - 4;

  // quit:
  const size_t quit = e.mark();
  e.db({0x48, 0xB9}); e.dq(ctl_va + kStatus);     // mov rcx, &status
  e.db({0x48, 0xC7, 0x01, 0x03, 0x00, 0x00, 0x00});  // mov qword [rcx], 3
  e.db({0x48, 0x83, 0xC4, 0x08});                 // add rsp, 8
  e.db({0x41, 0x59});                             // pop r9
  e.db({0x41, 0x58});                             // pop r8
  e.db({0x5A});                                   // pop rdx
  e.db({0x59});                                   // pop rcx
  e.db({0x58});                                   // pop rax
  e.db({0xC3});                                   // ret

  // ---- 回填 ----
  // je idle / je quit 用的是 disp32（因为先写了 0F 84 再 dq 占位）
  auto fix_rel32 = [&](size_t disp_at, size_t target) {
    const int64_t rel = static_cast<int64_t>(target) - static_cast<int64_t>(disp_at + 4);
    const int32_t r32 = static_cast<int32_t>(rel);
    std::memcpy(e.c.data() + disp_at, &r32, 4);
  };
  fix_rel32(je_idle_at, idle);
  fix_rel32(je_quit_at, quit);
  fix_rel32(jmp_loop_at, loop);
  // rel8 语义：相对"下一条指令"的偏移
  e.c[jne_disp_at] = static_cast<uint8_t>(skip_call - (jne_disp_at + 1));
  e.c[je_sleep_disp_at] = static_cast<uint8_t>(skip_sleep - (je_sleep_disp_at + 1));
  return e.c;
}

}  // namespace win
}  // namespace wowmod
#endif
