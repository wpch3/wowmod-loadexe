// 跳板语义离线验证器。
//
// 为什么需要：跳板的机器码是运行时拼出来的，一旦有错就是客户端崩溃，
// 代价是用户的一次完整启动 + 一次崩溃。这里用纯软件模拟把「生成的字节
// 到底干了什么」在本地解出来，顺序执行并比对结果 —— 不依赖 Windows，
// 也不依赖客户端。
//
// 做法：只实现这些跳板用得到的指令子集（mov/push/sub/lea/call/test/cmp/
// jcc/xor/add/jmp/cmp-mem），逐条解释执行，遇到 jmp <trampoline> 或 ret 就停。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wowmod {
namespace x64sim {

// 一台极简 x64 解释器：只够跑我们自己的跳板。
struct Cpu {
  uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
  uint64_t rsi = 0, rdi = 0, rsp = 0, rbp = 0;
  uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
  // 平坦内存：地址 -> 1 字节。只放我们要用的表和数据。
  std::map<uint64_t, uint8_t> mem;
  bool jf = false, zf = false, sf = false, cf = false;
  uint64_t rip = 0;
  uint64_t rsp_valid_base = 0;   // 栈底（模拟用，不真实分配）

  uint64_t* reg(int idx);
  uint64_t read64(uint64_t a) const;
  uint32_t read32(uint64_t a) const;
  void write64(uint64_t a, uint64_t v);
  void write32(uint64_t a, uint32_t v);
  void push(uint64_t v);
  uint64_t pop();
};

enum class Stop : int {
  kReturn = 0,    // 执行到 ret
  kJumpOut = 1,   // 跳到跳板外（trampoline / 原函数）
  kBadDecode = 2, // 遇到不认识的字节
  kRange = 3,     // 越界
  kMaxSteps = 4,
};

struct SimResult {
  Stop stop = Stop::kBadDecode;
  uint64_t steps = 0;
  uint64_t jump_target = 0;   // kJumpOut 时的目标
  uint64_t returned = 0;      // kReturn 时 rax 的值（返回值）
  std::string error;
  std::vector<std::string> trace;  // 逐条执行记录，失败时用于定位
};

// 执行一段代码。code 会按 va 映射进内存。
// 参数：按 Windows x64 约定布置 rcx/rdx/r8/r9，并准备好栈。
SimResult run(const std::vector<uint8_t>& code, uint64_t va,
              uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t rsp);

}  // namespace x64sim
}  // namespace wowmod
