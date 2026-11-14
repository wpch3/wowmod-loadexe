// 「旁路记录」跳板的字节生成实现。
// SPDX-License-Identifier: MIT
#include "wowmod/probe_stub.hpp"

#include <cstdio>
#include <cstring>

namespace wowmod {

namespace {

// 极简 x64 字节发射器。
class Emit {
 public:
  std::vector<uint8_t> code;

  size_t pos() const { return code.size(); }
  void db(uint8_t b) { code.push_back(b); }
  void db(std::initializer_list<uint8_t> bs) {
    code.insert(code.end(), bs.begin(), bs.end());
  }
  void dd(uint32_t v) {
    const size_t at = code.size();
    code.resize(at + 4);
    std::memcpy(code.data() + at, &v, 4);
  }
  void dq(uint64_t v) {
    const size_t at = code.size();
    code.resize(at + 8);
    std::memcpy(code.data() + at, &v, 8);
  }
  static uint8_t modrm(int mod, int reg, int rm) {
    return static_cast<uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7));
  }
};

constexpr uint8_t kRax = 0, kRcx = 1, kRdx = 2;
constexpr uint8_t kRsp = 4;
constexpr uint8_t kR10 = 10, kR11 = 11;

struct RegName {
  const char* name;
  int num;
};

const RegName kRegs[] = {
    {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3}, {"rsp", 4}, {"rbp", 5},
    {"rsi", 6}, {"rdi", 7}, {"r8", 8},  {"r9", 9},  {"r10", 10}, {"r11", 11},
    {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
    {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3}, {"esp", 4}, {"ebp", 5},
    {"esi", 6}, {"edi", 7}, {"r8d", 8}, {"r9d", 9}, {"r10d", 10}, {"r11d", 11},
    {"r12d", 12}, {"r13d", 13}, {"r14d", 14}, {"r15d", 15},
};

}  // namespace

int register_number(const std::string& name) {
  for (const auto& r : kRegs) {
    if (name == r.name) return r.num;
  }
  return -1;
}

std::string ProbeStubResult::describe() const {
  if (ok()) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "probe stub: %zu 字节, %zu 个待回填槽", code.size(),
                  patch_slots.size());
    return buf;
  }
  std::string s = "probe stub 生成失败:";
  for (const auto& e : errors) s += "\n  - " + e;
  return s;
}

// 跳板做的事（全程 32 位操作数，不碰任何寄存器的高 32 位）：
//
//   push rax / rcx / rdx / r10 / r11 / pushfq     ; 保存现场
//   mov  r10, <buffer_va>
//   mov  r11d, <id_reg32>                        ; 只读它，不改它
//   total++
//   槽位 = r10 + 0x18 + head*16
//   [槽位+0]  = id
//   [槽位+12] = total                            ; seq，用于判断数据新鲜度
//   head = (head + 1) & (capacity - 1)
//   popfq / pop r11 / r10 / rdx / rcx / rax      ; 恢复现场
//   jmp  qword ptr [rip+0] <trampoline>          ; 执行被搬走的原始指令
//
// 关键：不写返回寄存器、不改任何状态，控制流与原始代码完全等价。
// 保存 r10/r11 是因为它们被本跳板占用，而「被搬走的原始指令」可能用到它们。
ProbeStubResult build_probe_stub(const ProbeStubConfig& cfg, uint64_t buffer_va) {
  ProbeStubResult r;
  Emit e;

  const int idnum = cfg.id_reg;
  if (idnum < 0 || idnum > 15) {
    r.errors.push_back("id_reg 越界（应为 0..15）");
    return r;
  }
  if (idnum == kRsp) {
    r.errors.push_back("id_reg 不能是 rsp");
    return r;
  }
  if (cfg.capacity == 0 || (cfg.capacity & (cfg.capacity - 1)) != 0) {
    r.errors.push_back("capacity 必须是 2 的幂");
    return r;
  }

  // ---- 保存现场 ----
  e.db({0x50});          // push rax
  e.db({0x51});          // push rcx
  e.db({0x52});          // push rdx
  e.db({0x41, 0x52});    // push r10
  e.db({0x41, 0x53});    // push r11
  e.db({0x9C});          // pushfq

  // ---- mov r10, buffer_va ----
  e.db({0x49, 0xBA});
  e.dq(buffer_va);

  // ---- mov r11d, id_reg ----
  {
    const bool rr = idnum >= 8;   // REX.R
    e.db(static_cast<uint8_t>(0x44 | (rr ? 0x04 : 0x00)));
    e.db(0x8B);
    e.db(Emit::modrm(3, kR11, idnum));
  }

  // ---- total++ ----
  e.db({0x41, 0x8B, 0x42, static_cast<uint8_t>(ProbeBufferLayout::kTotalOff)});  // mov eax,[r10+T]
  e.db({0xFF, 0xC0});                                                            // inc eax
  e.db({0x41, 0x89, 0x42, static_cast<uint8_t>(ProbeBufferLayout::kTotalOff)});  // mov [r10+T],eax

  // ---- 槽位地址 = r10 + head*16 ----
  e.db({0x41, 0x8B, 0x4A, static_cast<uint8_t>(ProbeBufferLayout::kHeadOff)});   // mov ecx,[r10+H]
  e.db({0x89, 0xCA});                       // mov edx, ecx
  e.db({0xC1, 0xE2, 0x04});                 // shl edx, 4
  e.db({0x4C, 0x01, 0xD2});                 // add rdx, r10

  // ---- [rdx + 0x18] = id ----
  e.db({0x44, 0x89});                                   // mov r/m32, r11d
  e.db(Emit::modrm(1, kR11, kRdx));                     // mod=01 (disp8), rm=rdx
  e.db(static_cast<uint8_t>(ProbeBufferLayout::kSlotsOff));   // 0x18

  // ---- [rdx + 0x24] = seq（槽位 +12）----
  e.db({0x89});                                         // mov r/m32, eax
  e.db(Emit::modrm(1, kRax, kRdx));
  e.db(static_cast<uint8_t>(ProbeBufferLayout::kSlotsOff + ProbeBufferLayout::kSlotSeqOff));

  // ---- head = (head+1) & (cap-1) ----
  e.db({0xFF, 0xC1});                       // inc ecx
  e.db({0x81, 0xE1});                       // and ecx, imm32
  e.dd(cfg.capacity - 1);
  e.db({0x41, 0x89, 0x4A, static_cast<uint8_t>(ProbeBufferLayout::kHeadOff)});   // mov [r10+H],ecx

  // ---- 恢复现场 ----
  e.db({0x9D});          // popfq
  e.db({0x41, 0x5B});    // pop r11
  e.db({0x41, 0x5A});    // pop r10
  e.db({0x5A});          // pop rdx
  e.db({0x59});          // pop rcx
  e.db({0x58});          // pop rax

  // ---- 跳回 trampoline ----
  e.db({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
  r.patch_slots.push_back({static_cast<int>(e.pos()), "trampoline_va"});
  e.dq(0);

  r.code = std::move(e.code);
  return r;
}

}  // namespace wowmod
