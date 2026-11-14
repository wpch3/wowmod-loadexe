// x86-64 指令长度解码实现（长度 + ModRM/SIB/disp/imm 计算 + 相对位移识别）。
// SPDX-License-Identifier: MIT
#include "wowmod/x64_decode.hpp"

#include <cstdio>
#include <cstring>
#include <climits>

namespace wowmod {
namespace x64 {

namespace {

// 一字节 opcode 的立即数宽度表：0=无, 1=ib, 2=iz(2/4), 4=id(4), 8=iq(8), 10=o(取决于操作数宽度)
enum : uint8_t { IMM_NONE = 0, IMM_8 = 1, IMM_16 = 2, IMM_Z = 3, IMM_32 = 4, IMM_64 = 8, IMM_OSIZE = 10 };

struct OpInfo {
  bool modrm = false;
  uint8_t imm = IMM_NONE;
};

// 一字节映射（legacy）。未列出的 opcode 视为 Invalid。
OpInfo one_byte(uint8_t op) {
  // 0x00-0x3F：算术组。注意 op>=0x40 的 REX 前缀已在 decode() 中消费，
  // 这里收到的一定是真正的 opcode，不能再用 (op&7) 猜测。
  if (op <= 0x05) return {op <= 0x03, op == 0x04 ? IMM_8 : (op == 0x05 ? IMM_Z : IMM_NONE)};
  if (op >= 0x08 && op <= 0x0d)
    return {op <= 0x0b, op == 0x0c ? IMM_8 : (op == 0x0d ? IMM_Z : IMM_NONE)};
  if (op >= 0x10 && op <= 0x15)
    return {op <= 0x13, op == 0x14 ? IMM_8 : (op == 0x15 ? IMM_Z : IMM_NONE)};
  if (op >= 0x18 && op <= 0x1d)
    return {op <= 0x1b, op == 0x1c ? IMM_8 : (op == 0x1d ? IMM_Z : IMM_NONE)};
  if (op >= 0x20 && op <= 0x25)
    return {op <= 0x23, op == 0x24 ? IMM_8 : (op == 0x25 ? IMM_Z : IMM_NONE)};
  if (op >= 0x28 && op <= 0x2d)
    return {op <= 0x2b, op == 0x2c ? IMM_8 : (op == 0x2d ? IMM_Z : IMM_NONE)};
  if (op >= 0x30 && op <= 0x35)
    return {op <= 0x33, op == 0x34 ? IMM_8 : (op == 0x35 ? IMM_Z : IMM_NONE)};
  if (op >= 0x38 && op <= 0x3d)
    return {op <= 0x3b, op == 0x3c ? IMM_8 : (op == 0x3d ? IMM_Z : IMM_NONE)};
  if (op >= 0x50 && op <= 0x5F) return {false, IMM_NONE};       // push/pop r64
  if (op == 0x60 || op == 0x61) return {false, IMM_NONE};       // invalid in 64-bit but decode
  if (op == 0x62) return {true, IMM_NONE};                       // EVEX (64-bit)
  if (op == 0x63) return {true, IMM_NONE};                       // movsxd
  if (op == 0x68) return {false, IMM_32};                        // push imm32
  if (op == 0x69) return {true, IMM_Z};                         // imul r, r/m, imm32
  if (op == 0x6A) return {false, IMM_8};                         // push imm8
  if (op == 0x6B) return {true, IMM_8};                          // imul r, r/m, imm8
  if (op >= 0x6C && op <= 0x6F) return {false, IMM_NONE};        // ins/outs
  if (op >= 0x70 && op <= 0x7F) return {false, IMM_8};           // jcc rel8
  if (op == 0x80) return {true, IMM_8};
  if (op == 0x81) return {true, IMM_Z};
  if (op == 0x82) return {true, IMM_8};                          // invalid in 64-bit
  if (op == 0x83) return {true, IMM_8};
  if (op >= 0x84 && op <= 0x8F) return {true, IMM_NONE};
  if (op >= 0x90 && op <= 0x9F) return {false, IMM_NONE};
  if (op >= 0xA0 && op <= 0xA3) return {false, IMM_64};          // moffs64
  if (op >= 0xA4 && op <= 0xA7) return {false, IMM_NONE};        // movs/cmps（无 ModRM、无立即数）
  if (op == 0xA8) return {false, IMM_8};
  if (op == 0xA9) return {false, IMM_Z};
  if (op >= 0xAA && op <= 0xAF) return {false, IMM_NONE};
  if (op >= 0xB0 && op <= 0xB7) return {false, IMM_8};           // mov r8, imm8
  if (op >= 0xB8 && op <= 0xBF) return {false, IMM_64};          // mov r, imm64/imm32（宽度看 REX.W）
  if (op == 0xC0 || op == 0xC1) return {true, IMM_8};
  if (op == 0xC2) return {false, IMM_16};                        // ret imm16
  if (op == 0xC3) return {false, IMM_NONE};
  if (op == 0xC4 || op == 0xC5) return {false, IMM_NONE};        // VEX（单独处理）
  if (op == 0xC6) return {true, IMM_8};
  if (op == 0xC7) return {true, IMM_Z};
  if (op == 0xC8) return {false, IMM_16};                        // enter iw, ib
  if (op == 0xC9) return {false, IMM_NONE};
  if (op == 0xCA) return {false, IMM_16};
  if (op == 0xCB) return {false, IMM_NONE};
  if (op == 0xCC) return {false, IMM_NONE};
  if (op == 0xCD) return {false, IMM_8};
  if (op == 0xCE || op == 0xCF) return {false, IMM_NONE};
  if (op >= 0xD0 && op <= 0xD3) return {true, IMM_NONE};
  if (op == 0xD4 || op == 0xD5) return {false, IMM_8};
  if (op == 0xD7) return {false, IMM_NONE};
  if (op >= 0xD8 && op <= 0xDF) return {true, IMM_NONE};         // x87
  if (op >= 0xE0 && op <= 0xE3) return {false, IMM_8};           // loop/jcxz
  if (op >= 0xE4 && op <= 0xE7) return {false, IMM_8};
  if (op == 0xE8 || op == 0xE9) return {false, IMM_32};          // call/jmp rel32
  if (op == 0xEA) return {false, IMM_32};                        // invalid in 64-bit
  if (op == 0xEB) return {false, IMM_8};                         // jmp rel8
  if (op >= 0xEC && op <= 0xEF) return {false, IMM_NONE};
  if (op == 0xF1) return {false, IMM_NONE};
  if (op == 0xF4) return {false, IMM_NONE};
  if (op == 0xF5) return {false, IMM_NONE};
  if (op == 0xF6) return {true, IMM_8};    // /0,/1 是 test r/m8, imm8；其他无立即数
  if (op == 0xF7) return {true, IMM_Z};
  if (op >= 0xF8 && op <= 0xFD) return {false, IMM_NONE};
  if (op == 0xFE) return {true, IMM_NONE};
  if (op == 0xFF) return {true, IMM_NONE};
  return {false, 0xFF /*invalid*/};
}

OpInfo two_byte(uint8_t op) {
  if (op <= 0x03) return {true, IMM_NONE};
  if (op == 0x04 || op == 0x05) return {false, IMM_NONE};
  if (op == 0x06 || op == 0x07 || op == 0x08 || op == 0x09 || op == 0x0B ||
      op == 0x0E) return {false, IMM_NONE};
  if (op == 0x0D) return {true, IMM_NONE};
  if (op >= 0x0F && op <= 0x1F) return {true, IMM_NONE};
  if (op >= 0x20 && op <= 0x23) return {true, IMM_NONE};
  if (op >= 0x24 && op <= 0x27) return {true, IMM_NONE};  // invalid but length-decodable
  if (op >= 0x28 && op <= 0x2F) return {true, IMM_NONE};
  if (op >= 0x30 && op <= 0x37) return {false, IMM_NONE};  // wrmsr/rdtsc/...
  if (op >= 0x38 && op <= 0x3F) return {false, IMM_NONE};  // 0x38/0x3A 是三字节映射
  if (op >= 0x40 && op <= 0x4F) return {true, IMM_NONE};  // cmovcc
  if (op >= 0x50 && op <= 0x6F) return {true, IMM_NONE};  // SSE/MMX
  if (op >= 0x70 && op <= 0x73) return {true, IMM_8};
  if (op >= 0x74 && op <= 0x76) return {true, IMM_NONE};
  if (op == 0x77) return {false, IMM_NONE};               // emms
  if (op >= 0x78 && op <= 0x7F) return {true, IMM_NONE};
  if (op >= 0x80 && op <= 0x8F) return {false, IMM_32};   // jcc rel32
  if (op >= 0x90 && op <= 0x9F) return {true, IMM_NONE};  // setcc
  if (op >= 0xA0 && op <= 0xA1) return {false, IMM_NONE}; // push/pop fs
  if (op == 0xA2) return {false, IMM_NONE};
  if (op == 0xA3) return {true, IMM_NONE};
  if ((op == 0xA4 || op == 0xAC) && op != 0xA7) return {true, IMM_8};  // shld r/m,r,imm8 (0F A4/AC)
  if (op == 0xA8 || op == 0xA9) return {false, IMM_NONE};
  if (op == 0xAA) return {false, IMM_NONE};
  if (op == 0xAB) return {true, IMM_NONE};
  if (op == 0xAE) return {true, IMM_NONE};
  if (op == 0xAF) return {true, IMM_NONE};
  if (op == 0xBA) return {true, IMM_8};                  // bt/bts/btr/btc r/m, imm8
  if (op >= 0xB0 && op <= 0xBF) return {true, IMM_NONE};
  if (op >= 0xC0 && op <= 0xC1) return {true, IMM_NONE};
  if (op >= 0xC2 && op <= 0xC6 && op != 0xC3) return {true, IMM_8};  // cmpps/pinsrw/pextrw/shufps
  if (op == 0xC3) return {true, IMM_NONE};                          // movnti
  if (op == 0xC7) return {true, IMM_NONE};
  if (op >= 0xC8 && op <= 0xCF) return {false, IMM_NONE};  // bswap r64
  if (op >= 0xD0) return {true, IMM_NONE};
  return {true, IMM_NONE};
}

}  // namespace

DecodedInsn decode(const uint8_t* buf, size_t len) {
  DecodedInsn out;
  if (!buf || len == 0) return out;

  size_t i = 0;
  bool rex_w = false;
  bool addr_size_16 = false;
  bool opsize_16 = false;
  bool is_vex = false, is_evex = false;
  uint8_t vex_map = 0;

  // ---- 前缀 ----
  for (;;) {
    if (i >= len) return out;
    const uint8_t b = buf[i];
    if (b == 0x66) { opsize_16 = true; ++i; continue; }
    if (b == 0x67) { addr_size_16 = true; ++i; continue; }
    if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
        b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { ++i; continue; }
    break;
  }
  // REX 必须在所有 legacy 前缀之后
  if (i < len && (buf[i] & 0xF0) == 0x40) {
    rex_w = (buf[i] & 0x08) != 0;
    ++i;
  }
  if (i >= len) return out;

  // ---- VEX / EVEX ----
  OpInfo info;
  uint8_t opcode = 0;
  if (buf[i] == 0xC5) {
    is_vex = true;
    vex_map = 1;
    if (i + 2 >= len) return out;
    i += 2;  // C5 + 1 byte
    if (i >= len) return out;
    opcode = buf[i++];
  } else if (buf[i] == 0xC4) {
    is_vex = true;
    if (i + 3 >= len) return out;
    vex_map = buf[i + 1] & 0x1F;
    i += 3;  // C4 + 2 bytes
    if (i >= len) return out;
    opcode = buf[i++];
  } else if (buf[i] == 0x62) {
    is_evex = true;
    if (i + 4 >= len) return out;
    vex_map = buf[i + 1] & 0x07;
    i += 4;  // 62 + P0 + P1 + P2
    if (i >= len) return out;
    opcode = buf[i++];
  } else {
    opcode = buf[i++];
  }

  bool has_modrm = true;
  uint8_t imm = IMM_NONE;
  bool is_two = false;

  if (is_vex || is_evex) {
    has_modrm = !(is_vex && vex_map == 1 && (opcode == 0x77));  // vzeroupper
    // VEX/EVEX 的立即数只出现在少数 opcode 上
    if ((vex_map == 1 && (opcode == 0x70 || opcode == 0x71 || opcode == 0x72 || opcode == 0x73 ||
                          opcode == 0xC2 || opcode == 0xC4 || opcode == 0xC5 || opcode == 0xC6))) {
      imm = IMM_8;
    }
    if (vex_map == 3) {  // 0F3A 全部带 imm8
      imm = IMM_8;
    }
  } else if (opcode == 0x0F) {
    is_two = true;
    if (i >= len) return out;
    const uint8_t op2 = buf[i++];
    if (op2 == 0x38) {
      if (i >= len) return out;
      opcode = buf[i++];  // 三字节映射：0F 38 xx
      has_modrm = true;
      imm = IMM_NONE;
    } else if (op2 == 0x3A) {
      if (i >= len) return out;
      opcode = buf[i++];  // 0F 3A xx，全部带 imm8
      has_modrm = true;
      imm = IMM_8;
    } else {
      info = two_byte(op2);
      has_modrm = info.modrm;
      imm = info.imm;
      out.opcode2 = op2;
      opcode = 0x0F;  // 保留映射信息
    }
  } else {
    info = one_byte(opcode);
    has_modrm = info.modrm;
    imm = info.imm;
  }

  // ---- ModRM + SIB + disp ----
  uint8_t modrm = 0;
  if (has_modrm) {
    if (i >= len) return out;
    modrm = buf[i++];
    const uint8_t mod = modrm >> 6;
    const uint8_t rm = modrm & 7;
    bool disp32_only = false;
    if (mod != 3) {
      if (addr_size_16) {
        // 16 位寻址（少见，仅 0x67 前缀）：mod=0/1/2 用 disp16
        if (mod == 0) { /* [bx+si] 无 disp */ }
        else if (mod == 1) { if (i + 1 > len) return out; i += 1; }
        else { if (i + 2 > len) return out; i += 2; }
        (void)0;
      } else {
        if (rm == 4) {  // SIB
          if (i >= len) return out;
          const uint8_t sib = buf[i++];
          const uint8_t base = sib & 7;
          if (mod == 0 && base == 5) disp32_only = true;
        } else if (mod == 0 && rm == 5) {
          // RIP 相对（64 位默认）
          disp32_only = true;
          out.is_rip_relative = true;
          out.rip_disp_offset = i;
        }
        if (mod == 0) {
          if (disp32_only) { if (i + 4 > len) return out; i += 4; }
        } else if (mod == 1) {
          if (i + 1 > len) return out;
          i += 1;
        } else {
          if (i + 4 > len) return out;
          i += 4;
        }
      }
    }
  }

  // ---- 立即数 ----
  // 0xF6/0xF7 只有 /0（test）和 /1（test，保留）带立即数；not/neg/mul/imul/div/idiv 没有
  if ((imm == IMM_8 || imm == IMM_Z) && !is_two && (opcode == 0xF6 || opcode == 0xF7) && has_modrm) {
    const uint8_t reg = (modrm >> 3) & 7;
    if (reg > 1) imm = IMM_NONE;
  }
  switch (imm) {
    case IMM_8: if (i + 1 > len) return out; i += 1; break;
    case IMM_16: if (i + 2 > len) return out; i += 2; break;
    case IMM_32: if (i + 4 > len) return out; i += 4; break;
    case IMM_Z: {
      const size_t z = opsize_16 ? 2 : 4;
      if (i + z > len) return out;
      i += z;
      break;
    }
    case IMM_64:
      // B8..BF：REX.W -> imm64，否则 imm32（0x66 前缀 -> imm16）。
      // 其余 IMM_64（moffs A0..A3）在 64 位下始终是 8 字节。
      if (opcode >= 0xB8 && opcode <= 0xBF) {
        size_t w = rex_w ? 8 : (opsize_16 ? 2 : 4);
        if (i + w > len) return out;
        i += w;
      } else {
        if (i + 8 > len) return out;
        i += 8;
      }
      break;
    case IMM_OSIZE:
      if (rex_w) { if (i + 8 > len) return out; i += (opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA3) ? 8 : 4; }
      else if (opsize_16) { if (i + 2 > len) return out; i += 2; }
      else { if (i + 4 > len) return out; i += 4; }
      break;
    case IMM_NONE: break;
    default: return out;  // 0xFF = 无法识别的 opcode
  }

  if (i > 15) return out;  // x86 指令最长 15 字节
  out.length = static_cast<uint8_t>(i);
  out.has_modrm = has_modrm;
  out.opcode = opcode;

  const uint8_t lead = buf[0];
  // 语义标记（只用于搬运策略，不做反汇编）
  if (!is_vex && !is_evex) {
    if (lead == 0xC3 || lead == 0xCB || lead == 0xC2 || lead == 0xCA) out.is_ret = true;
    if (lead == 0xCC || (lead == 0x0F && opcode == 0x0B) || lead == 0xF4) out.is_terminator = true;
  }
  if (!is_vex && !is_evex) {
    if (lead == 0xE8 || lead == 0xE9 || lead == 0xEB || (lead >= 0x70 && lead <= 0x7F) ||
        (lead == 0x0F && opcode >= 0x80 && opcode <= 0x8F && out.opcode2 >= 0x80)) {
      out.is_jump = true;
    }
    if (lead == 0xE9 || lead == 0xEB) out.is_terminator = true;
  }
  if (out.is_rip_relative && out.length >= out.rip_disp_offset + 4) {
    int32_t d;
    std::memcpy(&d, buf + out.rip_disp_offset, 4);
    out.rip_disp = d;
  }
  return out;
}

size_t find_safe_split(const uint8_t* buf, size_t len, size_t offset, size_t want) {
  if (!buf || offset >= len) return 0;
  size_t pos = offset;
  while (pos < len) {
    const DecodedInsn insn = decode(buf + pos, len - pos);
    if (insn.length == 0) return 0;
    pos += insn.length;
    if (pos - offset >= want) return pos - offset;
    if (pos - offset > 32) return 0;  // 吞噬过多，说明特征位置不对
  }
  return 0;
}

bool is_instruction_aligned(const uint8_t* buf, size_t len, size_t offset, size_t n) {
  if (!buf || offset + n > len) return false;
  size_t pos = offset;
  while (pos < offset + n) {
    const DecodedInsn insn = decode(buf + pos, len - pos);
    if (insn.length == 0) return false;
    pos += insn.length;
  }
  return pos == offset + n;
}

bool relocate_block(std::vector<uint8_t>& code, uint64_t src, uint64_t dst) {
  size_t pos = 0;
  while (pos < code.size()) {
    DecodedInsn insn = decode(code.data() + pos, code.size() - pos);
    if (insn.length == 0) return false;

    // RIP 相对寻址：重算 disp32
    if (insn.is_rip_relative) {
      const uint64_t old_target = src + pos + insn.length + static_cast<int64_t>(insn.rip_disp);
      const int64_t new_disp = static_cast<int64_t>(old_target) -
                               static_cast<int64_t>(dst + pos + insn.length);
      if (new_disp > INT32_MAX || new_disp < INT32_MIN) return false;
      std::memcpy(code.data() + pos + insn.rip_disp_offset, &new_disp, 4);
    }

    // rel8/rel32 跳转：重算
    if (insn.is_jump) {
      // 找到位移字段：0F 8x -> 末尾 4 字节；E8/E9 -> 末尾 4；E*/70-7F/EB -> 末尾 1
      size_t disp_off = 0;
      size_t disp_size = 0;
      // 跳过前缀定位 opcode
      size_t k = pos;
      while (k < code.size()) {
        const uint8_t b = code[k];
        if (b == 0x66 || b == 0x67 || (b & 0xF0) == 0x40 || b == 0xF0 || b == 0xF2 ||
            b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
          ++k;
          continue;
        }
        break;
      }
      if (k >= code.size()) return false;
      const uint8_t op = code[k];
      if (op == 0x0F) {
        disp_size = 4;
      } else if (op == 0xE8 || op == 0xE9) {
        disp_size = 4;
      } else if ((op >= 0x70 && op <= 0x7F) || op == 0xEB) {
        disp_size = 1;
      } else {
        disp_size = 0;
      }
      if (disp_size) {
        disp_off = pos + insn.length - disp_size;
        const int64_t old_target_delta = disp_size == 1
                                             ? static_cast<int8_t>(code[disp_off])
                                             : *reinterpret_cast<int32_t*>(code.data() + disp_off);
        const uint64_t old_target = src + pos + insn.length + old_target_delta;
        const int64_t new_delta = static_cast<int64_t>(old_target) -
                                  static_cast<int64_t>(dst + pos + insn.length);
        if (disp_size == 1) {
          if (new_delta > 127 || new_delta < -128) return false;
          code[disp_off] = static_cast<uint8_t>(static_cast<int8_t>(new_delta));
        } else {
          if (new_delta > INT32_MAX || new_delta < INT32_MIN) return false;
          const int32_t d32 = static_cast<int32_t>(new_delta);
          std::memcpy(code.data() + disp_off, &d32, 4);
        }
      }
    }
    pos += insn.length;
  }
  return true;
}

const char* opcode_name(const DecodedInsn& insn) {
  if (insn.length == 0) return "invalid";
  if (insn.opcode2) {
    static char buf[16];
    std::snprintf(buf, sizeof(buf), "0f%02x", insn.opcode2);
    return buf;
  }
  static char buf[8];
  std::snprintf(buf, sizeof(buf), "%02x", insn.opcode);
  return buf;
}

}  // namespace x64
}  // namespace wowmod
