// 拦截跳板的机器码生成。纯字节，无平台依赖 —— 见头文件里的语义约定。
// SPDX-License-Identifier: MIT
#include "wowmod/intercept_stub.hpp"

#include <cstring>

namespace wowmod {

std::vector<uint8_t> build_intercept_stub_bytes(uint64_t counter_va, uint64_t ring_va,
                                                uint32_t ring_mask) {
  std::vector<uint8_t> c;
  auto db = [&](std::initializer_list<uint8_t> bs) { c.insert(c.end(), bs.begin(), bs.end()); };
  auto dq = [&](uint64_t v) {
    const size_t at = c.size();
    c.resize(at + 8);
    std::memcpy(c.data() + at, &v, 8);
  };
  auto dd = [&](uint32_t v) {
    const size_t at = c.size();
    c.resize(at + 4);
    std::memcpy(c.data() + at, &v, 4);
  };

  // 不破坏任何寄存器：先全部压栈保存，记录完再恢复。
  db({0x50});              // push rax
  db({0x51});              // push rcx
  db({0x52});              // push rdx
  db({0x41, 0x50});        // push r8
  db({0x41, 0x51});        // push r9

  db({0x49, 0xBA}); dq(counter_va);   // mov r10, counter
  db({0x49, 0xBB}); dq(ring_va);      // mov r11, ring

  // 槽位用【自增前】的计数：第一次调用写 slot 0，计数器随后变成 1。
  // 早期版本先 inc 再取模，导致第一个槽永远空着，轮询端读 seq=1 时
  // 实际数据落在 slot1，很容易看错（这也是 tests 里那条回归测试的由来）。
  db({0x49, 0x8B, 0x02});             // mov rax, [r10]
  db({0x48, 0x25}); dd(ring_mask);    // and rax, mask
  db({0x48, 0xC1, 0xE0, 0x06});       // shl rax, 6
  db({0x4C, 0x01, 0xD8});             // add rax, r11   (rax = &record)

  // 写快照。压栈顺序 rax,rcx,rdx,r8,r9 -> 栈上：
  //   [rsp+0x00]=r9 [rsp+0x08]=r8 [rsp+0x10]=rdx [rsp+0x18]=rcx [rsp+0x20]=rax
  db({0x48, 0x8B, 0x4C, 0x24, 0x20}); db({0x48, 0x89, 0x08});      // rax
  db({0x48, 0x8B, 0x4C, 0x24, 0x18}); db({0x48, 0x89, 0x48, 0x08}); // rcx
  db({0x48, 0x8B, 0x4C, 0x24, 0x10}); db({0x48, 0x89, 0x48, 0x10}); // rdx
  db({0x4C, 0x89, 0x40, 0x18});       // mov [rax+0x18], r8
  db({0x4C, 0x89, 0x48, 0x20});       // mov [rax+0x20], r9
  db({0x48, 0x89, 0x60, 0x28});       // mov [rax+0x28], rsp

  // 序号 = 计数 + 1（本次调用的序号），然后计数器 +1
  db({0x49, 0x8B, 0x0A});             // mov rcx, [r10]
  db({0x48, 0xFF, 0xC1});             // inc rcx
  db({0x49, 0x89, 0x0A});             // mov [r10], rcx
  db({0x48, 0x89, 0x48, 0x30});       // mov [rax+0x30], rcx

  // 恢复寄存器
  db({0x41, 0x59});        // pop r9
  db({0x41, 0x58});        // pop r8
  db({0x5A});              // pop rdx
  db({0x59});              // pop rcx
  db({0x58});              // pop rax

  // 跳到 trampoline（原函数继续执行）
  db({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});  // jmp [rip+0]
  dq(0);                                     // 由调用方回填
  return c;
}

}  // namespace wowmod
