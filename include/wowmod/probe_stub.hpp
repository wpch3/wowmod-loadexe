// 「旁路记录」跳板生成器（只观察，不替换）。
//
// 为什么需要它：
//   我们已经把 12.0.7 的 FileDataID 查找函数定位到 RVA 0x33e06a0（CAS.cpp，
//   edx = FileDataID，返回查到的对象指针）。但在没有证据之前，【不能】直接把
//   返回值换成我们自己的指针 —— 那个对象 +0x10 处是什么结构我们还没验证，
//   猜错就是把垃圾指针当资源对象用，客户端必崩。
//
//   所以第一版 hook 只做一件事：把每次传入的 edx 记进一个环形缓冲，
//   然后原样执行被搬走的指令并跳回。全程不改任何返回值、不改任何寄存器结果。
//
// 跳板要做的事（与 fileid_stub 的区别：完全不碰返回值）：
//   1. 保存会被破坏的寄存器（含 rflags）
//   2. 把 id 写进环形缓冲：[head] = id; head = (head+1) % cap; count++
//   3. 恢复寄存器
//   4. 执行被 detour 搬走的原始指令（由 detour 的 trampoline 负责）
//   5. 跳回 trampoline
//
// 风险面：只新增一处写内存（缓冲区），不改变控制流的语义，也不改变返回值。
// 即使缓冲区写坏，最坏结果是日志不准，不会影响客户端加载资源。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {

// 环形缓冲在目标进程里的布局（固定，宿主侧按同样偏移读取）。
//
//   +0x00  u32 magic        = 0x574D5052 ('WMPR')
//   +0x04  u32 capacity     槽位数（由宿主决定）
//   +0x08  u32 head         下一个写入位置
//   +0x0C  u32 total        累计写入次数（会回绕，用于判断有没有新数据）
//   +0x10  u32 dropped      宿主读走之前的覆盖次数（= total - capacity 若溢出）
//   +0x14  u32 reserved
//   +0x18  ... 槽位数组，每槽 16 字节：
//            +0  u64 id           传入的 FileDataID（32 位零扩展）
//            +8  u32 hit_high     id 的高 32 位（检查是否脏）
//            +12 u32 seq          写入序号
struct ProbeBufferLayout {
  static constexpr uint32_t kMagic = 0x574D5052u;
  static constexpr size_t kMagicOff = 0x00;
  static constexpr size_t kCapacityOff = 0x04;
  static constexpr size_t kHeadOff = 0x08;
  static constexpr size_t kTotalOff = 0x0C;
  static constexpr size_t kDroppedOff = 0x10;
  static constexpr size_t kSlotsOff = 0x18;
  static constexpr size_t kSlotStride = 16;
  static constexpr size_t kSlotIdOff = 0;
  static constexpr size_t kSlotHighOff = 8;
  static constexpr size_t kSlotSeqOff = 12;

  static size_t bytes_for(uint32_t capacity) {
    return kSlotsOff + static_cast<size_t>(capacity) * kSlotStride;
  }
};

struct ProbeStubConfig {
  int id_reg = 2;   // 寄存器编号（0=rax 1=rcx 2=rdx 3=rbx 4=rsp 5=rbp 6=rsi 7=rdi）
                    // 0x33e06a0 的语义是 edx，所以默认 2。
  uint32_t capacity = 4096;
};

struct ProbeStubResult {
  std::vector<uint8_t> code;
  std::vector<std::string> errors;
  // code 内偏移 -> 需要填入的绝对值（由宿主导入目标进程地址后回填）
  std::vector<std::pair<int, std::string>> patch_slots;
  bool ok() const { return errors.empty() && !code.empty(); }
  std::string describe() const;
};

// 生成跳板。buffer_va 为环形缓冲在目标进程内的绝对地址。
// 生成的代码以「跳回 trampoline」结尾（trampoline_va 通过 patch_slots 回填）。
ProbeStubResult build_probe_stub(const ProbeStubConfig& cfg, uint64_t buffer_va);

// 把 id 寄存器名解析成 0..15 的编号（支持 rax/eax/ax/al 这一族）。
// 失败返回 -1。
int register_number(const std::string& name);

}  // namespace wowmod
