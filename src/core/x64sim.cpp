// 极简 x64 解释器，只覆盖我们自己生成的跳板用到的指令。
// SPDX-License-Identifier: MIT
#include "wowmod/x64sim.hpp"

#include <cstdio>
#include <cstring>
#include <sstream>

namespace wowmod {
namespace x64sim {
namespace {

bool is32(uint64_t v) { return v <= 0xFFFFFFFFull; }

}  // namespace

uint64_t* Cpu::reg(int idx) {
  switch (idx) {
    case 0: return &rax;
    case 1: return &rcx;
    case 2: return &rdx;
    case 3: return &rbx;
    case 4: return &rsp;
    case 5: return &rbp;
    case 6: return &rsi;
    case 7: return &rdi;
    case 8: return &r8;
    case 9: return &r9;
    case 10: return &r10;
    case 11: return &r11;
    case 12: return &r12;
    case 13: return &r13;
    case 14: return &r14;
    case 15: return &r15;
  }
  return nullptr;
}

uint64_t Cpu::read64(uint64_t a) const {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    auto it = mem.find(a + i);
    if (it == mem.end()) return 0;
    v |= static_cast<uint64_t>(it->second) << (8 * i);
  }
  return v;
}

uint32_t Cpu::read32(uint64_t a) const {
  uint32_t v = 0;
  for (int i = 0; i < 4; ++i) {
    auto it = mem.find(a + i);
    if (it == mem.end()) return 0;
    v |= static_cast<uint32_t>(it->second) << (8 * i);
  }
  return v;
}

void Cpu::write64(uint64_t a, uint64_t v) {
  for (int i = 0; i < 8; ++i) mem[a + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void Cpu::write32(uint64_t a, uint32_t v) {
  for (int i = 0; i < 4; ++i) mem[a + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

void Cpu::push(uint64_t v) {
  rsp -= 8;
  write64(rsp, v);
}

uint64_t Cpu::pop() {
  const uint64_t v = read64(rsp);
  rsp += 8;
  return v;
}

SimResult run(const std::vector<uint8_t>& code, uint64_t va,
              uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t rsp) {
  SimResult out;
  Cpu c;
  c.rcx = rcx;
  c.rdx = rdx;
  c.r8 = r8;
  c.r9 = r9;
  c.rsp = rsp;
  c.rip = va;
  for (size_t i = 0; i < code.size(); ++i) c.mem[va + i] = code[i];

  auto fail = [&](const std::string& why) {
    out.error = why;
    out.stop = Stop::kBadDecode;
    return out;
  };

  // 为了让 jmp qword [rip+X] 能"跳到外面"，我们把跳板之后的目标地址
  // 也当作合法目标识别，直接结束模拟。

  while (out.steps++ < 10000) {
    const uint64_t here = c.rip;
    auto at = [&](size_t off) -> uint8_t {
      auto it = c.mem.find(here + off);
      return it == c.mem.end() ? 0 : it->second;
    };

    std::ostringstream tr;
    tr << "0x" << std::hex << here;

    const uint8_t b0 = at(0);

    // ---- 0x85 test r/m32, r32（我们只生成同一寄存器的形式）----
    if (b0 == 0x85) {
      const uint8_t modrm = at(1);
      const int reg = (modrm >> 3) & 7, rm = modrm & 7;
      const uint64_t v = *c.reg(rm) & 0xFFFFFFFFull;
      c.zf = (v == 0);
      c.sf = ((v >> 31) & 1) != 0;
      c.cf = false;
      tr << "  test r" << rm << ", r" << reg;
      c.rip += 2;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- REX 前缀 ----
    int rex = 0;
    size_t p = 0;
    if ((b0 & 0xF0) == 0x40) {
      rex = b0;
      p = 1;
    }
    const bool W = (rex & 8) != 0;
    const int R = (rex & 4) ? 8 : 0;
    const int X = (rex & 2) ? 8 : 0;
    const int B = (rex & 1) ? 8 : 0;

    const uint8_t op = at(p);

    // ---- cmp r/m32, imm8 : 83 /7 ib（无 REX 或仅 REX.B）----
    if ((!rex || rex == 0x41) && op == 0x83 && ((at(p + 1) >> 3) & 7) == 7) {
      const int rd = (at(p + 1) & 7) + B;
      const uint32_t lhs = static_cast<uint32_t>(*c.reg(rd) & 0xFFFFFFFFull);
      const int32_t imm = static_cast<int8_t>(at(p + 2));
      const uint64_t r = static_cast<uint64_t>(lhs) - static_cast<uint64_t>(static_cast<int64_t>(imm));
      c.zf = (lhs == static_cast<uint32_t>(imm));
      c.sf = ((r >> 63) & 1) != 0;
      c.cf = lhs < static_cast<uint32_t>(imm);
      tr << "  cmp r" << rd << "d, " << imm;
      c.rip = here + p + 3;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- movabs r64, imm64 : REX.W + B8+rd ----
    if (W && (op & 0xF8) == 0xB8) {
      const int rd = (op & 7) + B;
      uint64_t imm = 0;
      for (int i = 0; i < 8; ++i) imm |= static_cast<uint64_t>(at(p + 1 + i)) << (8 * i);
      *c.reg(rd) = imm;
      tr << "  movabs r" << rd << ", 0x" << imm;
      c.rip = here + p + 9;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- push r64 : 0x50+rd ----
    if (p == 0 && (b0 & 0xF8) == 0x50) {
      const int rd = (b0 & 7) + B;
      c.push(*c.reg(rd));
      tr << "  push r" << rd;
      c.rip = here + 1;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- sub rsp, imm8 : 48 83 EC ib ----
    if (W && op == 0x83 && at(p + 1) == 0xEC) {
      const int imm = static_cast<int8_t>(at(p + 2));
      c.rsp -= static_cast<uint64_t>(imm);
      tr << "  sub rsp, " << imm;
      c.rip = here + p + 3;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- add r64, imm8 : REX.W 83 /0 ib ----
    if (W && op == 0x83) {
      const uint8_t modrm = at(p + 1);
      if (((modrm >> 3) & 7) == 0) {
        const int rd = (modrm & 7) + B;
        const int imm = static_cast<int8_t>(at(p + 2));
        *c.reg(rd) += static_cast<uint64_t>(static_cast<int64_t>(imm));
        tr << "  add r" << rd << ", " << imm;
        c.rip = here + p + 3;
        out.trace.push_back(tr.str());
        continue;
      }
      // cmp r/m64, imm32 : REX.W 81 /7 id
    }
    if (W && op == 0x81) {
      const uint8_t modrm = at(p + 1);
      const int sub = (modrm >> 3) & 7;
      const int rd = (modrm & 7) + B;
      uint32_t imm = 0;
      for (int i = 0; i < 4; ++i) imm |= static_cast<uint32_t>(at(p + 2 + i)) << (8 * i);
      const uint64_t lhs = *c.reg(rd);
      const uint64_t rhs = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(imm)));
      const uint64_t r = lhs - rhs;
      c.zf = (r == 0);
      c.sf = ((r >> 63) & 1) != 0;
      c.cf = lhs < rhs;
      tr << (sub == 7 ? "  cmp r" : "  ?? r") << rd << ", 0x" << imm;
      c.rip = here + p + 6;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- mov r64, r64 : REX.W 89 /r 或 8B /r ----
    if (W && (op == 0x89 || op == 0x8B) && (at(p + 1) >> 6) == 3) {
      const uint8_t modrm = at(p + 1);
      const int reg = ((modrm >> 3) & 7) + R;
      const int rm = (modrm & 7) + B;
      if (op == 0x89)
        *c.reg(rm) = *c.reg(reg);
      else
        *c.reg(reg) = *c.reg(rm);
      tr << "  mov";
      c.rip = here + p + 2;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- mov r64, [base + index + disp8] : REX.W 8B /r with SIB, mod=01 ----
    if (W && op == 0x8B && (at(p + 1) >> 6) == 1 && (at(p + 1) & 7) == 4) {
      const uint8_t modrm = at(p + 1);
      const int reg = ((modrm >> 3) & 7) + R;
      const uint8_t sib = at(p + 2);
      const int index = ((sib >> 3) & 7) + X;
      const int base = (sib & 7) + B;
      const int8_t disp = static_cast<int8_t>(at(p + 3));
      const uint64_t addr = *c.reg(base) + *c.reg(index) + static_cast<int64_t>(disp);
      *c.reg(reg) = c.read64(addr);
      tr << "  mov r" << reg << ", [r" << base << " + r" << index << " + " << (int)disp << "]";
      c.rip = here + p + 4;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- cmp id32, [base + index] : 3B /r with SIB mod=00 ----
    if (op == 0x3B && (at(p + 1) >> 6) == 0 && (at(p + 1) & 7) == 4) {
      const uint8_t modrm = at(p + 1);
      const int reg = ((modrm >> 3) & 7) + R;   // 被比较的寄存器（低 32 位）
      const uint8_t sib = at(p + 2);
      const int index = ((sib >> 3) & 7) + X;
      const int base = (sib & 7) + B;
      const uint64_t addr = *c.reg(base) + *c.reg(index);
      const uint32_t lhs = static_cast<uint32_t>(*c.reg(reg) & 0xFFFFFFFFull);
      const uint32_t rhs = c.read32(addr);
      const uint64_t r = static_cast<uint64_t>(lhs) - rhs;
      c.zf = (lhs == rhs);
      c.sf = ((r >> 63) & 1) != 0;
      c.cf = lhs < rhs;
      tr << "  cmp id32, [r" << base << " + r" << index << "] val=0x" << rhs;
      c.rip = here + p + 3;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- jcc rel8 : 0x70..0x7F ----
    if (!rex && (b0 & 0xF0) == 0x70) {
      const int cc = b0 & 0x0F;
      const int8_t rel = static_cast<int8_t>(at(1));
      bool take = false;
      switch (cc) {
        case 0x0: take = true; break;              // jo
        case 0x1: take = false; break;             // jno
        case 0x2: take = c.cf; break;              // jb
        case 0x3: take = !c.cf; break;             // jae
        case 0x4: take = c.zf; break;              // je
        case 0x5: take = !c.zf; break;             // jne
        case 0x8: take = c.sf; break;              // js
        case 0x9: take = !c.sf; break;             // jns
        default: return fail("不支持的 jcc cc=" + std::to_string(cc));
      }
      c.rip = take ? here + 2 + static_cast<int64_t>(rel) : here + 2;
      tr << "  jcc(cc=" << cc << (take ? " taken" : " not-taken") << ") -> 0x"
         << std::hex << c.rip;
      out.trace.push_back(tr.str());
      continue;
    }

    // ---- xor eax, eax : 33 C0 ----
    if (!rex && b0 == 0x33 && at(1) == 0xC0) {
      c.rax = 0;
      c.rip = here + 2;
      out.trace.push_back(tr.str() + "  xor eax, eax");
      continue;
    }
    // ---- xor r11d, r11d : 45 31 DB ----
    if (rex == 0x45 && op == 0x31 && at(p + 1) == 0xDB) {
      c.r11 = 0;
      c.rip = here + p + 2;
      out.trace.push_back(tr.str() + "  xor r11d, r11d");
      continue;
    }

    // ---- lea ecx, [rax + rax*2] : 8D 0C 40 ----
    if (!rex && b0 == 0x8D && at(1) == 0x0C && at(2) == 0x40) {
      c.rcx = (c.rax + c.rax * 2) & 0xFFFFFFFFull;
      c.rip = here + 3;
      out.trace.push_back(tr.str() + "  lea ecx, [rax+rax*2]");
      continue;
    }

    // ---- shl ecx, 2 : C1 E1 02 ----
    if (!rex && b0 == 0xC1 && at(1) == 0xE1 && at(2) == 0x02) {
      c.rcx = (c.rcx << 2) & 0xFFFFFFFFull;
      c.rip = here + 3;
      out.trace.push_back(tr.str() + "  shl ecx, 2");
      continue;
    }

    // ---- inc eax : FF C0 ----
    if (!rex && b0 == 0xFF && at(1) == 0xC0) {
      c.rax = (c.rax + 1) & 0xFFFFFFFFull;
      c.rip = here + 2;
      out.trace.push_back(tr.str() + "  inc eax");
      continue;
    }

    // ---- ret ----
    if (!rex && b0 == 0xC3) {
      out.stop = Stop::kReturn;
      out.returned = c.rax;
      out.trace.push_back(tr.str() + "  ret (rax=0x" + [&] {
        char b[32];
        std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(c.rax));
        return std::string(b);
      }() + ")");
      return out;
    }

    // ---- nop ----
    if (!rex && b0 == 0x90) {
      c.rip = here + 1;
      out.trace.push_back(tr.str() + "  nop");
      continue;
    }

    // ---- jmp qword [rip + disp32] : FF 25 disp32 ----
    if (!rex && b0 == 0xFF && at(1) == 0x25) {
      uint32_t disp = 0;
      for (int i = 0; i < 4; ++i) disp |= static_cast<uint32_t>(at(2 + i)) << (8 * i);
      const uint64_t slot = here + 6 + static_cast<int64_t>(static_cast<int32_t>(disp));
      const uint64_t target = c.read64(slot);
      out.stop = Stop::kJumpOut;
      out.jump_target = target;
      out.trace.push_back(tr.str() + "  jmp [rip+disp] -> 0x" + [&] {
        char b[32];
        std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(target));
        return std::string(b);
      }() + ")");
      return out;
    }

    // ---- jmp rax : FF E0 ----
    if (!rex && b0 == 0xFF && at(1) == 0xE0) {
      out.stop = Stop::kJumpOut;
      out.jump_target = c.rax;
      out.trace.push_back(tr.str() + "  jmp rax");
      return out;
    }

    return fail("未实现的字节序列 @" + [&] {
      char b[64];
      std::snprintf(b, sizeof(b), "0x%llx: %02X %02X %02X %02X",
                    static_cast<unsigned long long>(here), at(0), at(1), at(2), at(3));
      return std::string(b);
    }());
  }
  out.stop = Stop::kMaxSteps;
  out.error = "超过最大步数（可能是死循环）";
  return out;
}

}  // namespace x64sim
}  // namespace wowmod
