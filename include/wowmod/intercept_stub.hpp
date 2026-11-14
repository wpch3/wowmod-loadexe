// 拦截跳板的机器码生成（纯字节，不依赖任何平台头文件）。
//
// 单独抽出来的原因：这段机器码是【在客户端进程里跑的】，一旦有错就表现为
// 随机崩溃或记录全是垃圾，很难排查。抽成纯函数之后，测试可以直接把它
// 映射成可执行内存真的执行一遍（见 tests/intercept_test.cpp）。
//
// 语义约定（轮询端必须遵守，否则会整条错位）：
//   * 跳板用【自增前】的计数取槽：slot = counter & mask，然后把 counter+1。
//     所以第 seq 次调用（seq 从 1 开始）写的是 slot = (seq - 1) & mask。
//   * 记录里的 seq 字段 = 自增后的计数 = 本次调用的序号（从 1 开始）。
//   * 五个寄存器（rax/rcx/rdx/r8/r9）在调用后必须原样还原。
// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace wowmod {

// 记录槽字段偏移（64 字节一条）
struct InterceptRecordLayout {
  static constexpr size_t kRax = 0;
  static constexpr size_t kRcx = 8;
  static constexpr size_t kRdx = 16;
  static constexpr size_t kR8 = 24;
  static constexpr size_t kR9 = 32;
  static constexpr size_t kRsp = 40;
  static constexpr size_t kSeq = 48;
  static constexpr size_t kSize = 64;
};

// 生成拦截跳板：
//   counter_va —— 目标进程内 8 字节计数器
//   ring_va    —— 目标进程内环形缓冲（每条 64 字节）
//   ring_mask  —— 槽数 - 1（必须是 2^n - 1）
// 返回的字节末尾 8 字节是 trampoline 地址占位，调用方回填。
std::vector<uint8_t> build_intercept_stub_bytes(uint64_t counter_va, uint64_t ring_va,
                                                uint32_t ring_mask);

}  // namespace wowmod
