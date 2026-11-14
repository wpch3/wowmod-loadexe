// x86-64 指令长度解码器（只做长度/边界判定，不做语义反汇编）。
//
// 为什么需要它：在内联 detour 里，必须知道 hook 点上「完整指令」的边界。
// 公开的 Arctium 实现直接拷贝固定 13 字节并在其后跳回，
// 如果那 13 字节正好切断一条指令，之后的执行流会读到被截断的立即数/位移
// —— 这是「打上补丁后行为诡异/崩溃」最常见的原因之一。
// 本项目用长度解码器找到「≥ N 字节的最小指令边界」，只搬运完整指令。
//
// 覆盖范围：全部 legacy 前缀、REX、VEX2/VEX3、EVEX，一字节/0F/0F38/0F3A 映射，
// ModRM+SIB+disp，以及各种立即数宽度。不做语义解析，遇到无法识别的字节返回 0。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace x64 {

struct DecodedInsn {
  uint8_t length = 0;      // 0 = 无法解码
  bool has_modrm = false;
  bool is_ret = false;
  bool is_jump = false;      // jmp/jcc/call 相对跳转（目标是 rel32/rel8 位移）
  bool is_rip_relative = false;  // 含 RIP 相对寻址（搬运时需要处理）
  bool is_terminator = false;    // ret / int3 / ud2 / jmp（不可作为搬运尾部）
  uint8_t opcode = 0;
  uint8_t opcode2 = 0;      // 0F xx 的第二字节
  int32_t rip_disp = 0;     // RIP 相对 disp（若 is_rip_relative）
  size_t rip_disp_offset = 0;  // disp 在指令内的偏移
};

// 解码 buf[0..len) 处的一条指令。
DecodedInsn decode(const uint8_t* buf, size_t len);

// 从 offset 起寻找最小的指令边界，使得搬运长度 >= want。
// 成功返回搬运长度；失败返回 0（含 offset 处无法解码）。
size_t find_safe_split(const uint8_t* buf, size_t len, size_t offset, size_t want);

// 校验 [offset, offset+n) 是否落在完整指令边界上（全部指令都能干净解码）。
bool is_instruction_aligned(const uint8_t* buf, size_t len, size_t offset, size_t n);

// 把一段指令整体搬运到新地址时，修正如外的相对跳转 / RIP 相对寻址。
// src 为原地址，dst 为新地址；code 为搬运后的缓冲区，任何相对位移被重算。
// 返回 false 表示遇到无法修正的项（例如超出 rel32 范围）。
bool relocate_block(std::vector<uint8_t>& code, uint64_t src, uint64_t dst);

const char* opcode_name(const DecodedInsn& insn);

}  // namespace x64
}  // namespace wowmod
