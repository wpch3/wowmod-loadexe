// FileDataID 跳板代码生成实现。
//
// 这里手写了一个极小的「标签汇编器」：所有条件跳转都用标签 + 回填实现，
// 不再手工计算 rel8（那是上一个版本出错的地方）。寄存器编码统一走 rex()/modrm()，
// 因此 r8-r15 与 rax-r15 混用不会漏掉 REX 前缀。
// SPDX-License-Identifier: MIT
#include "wowmod/fileid_stub.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace wowmod {

namespace {

struct Reg32Info {
  int index;   // 0..15
  bool needs_rex;
};

bool lookup_reg32(const std::string& n, Reg32Info* out) {
  static const char* names32[16] = {"eax", "ecx", "edx",  "ebx", "esp", "ebp",  "esi", "edi",
                                    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
  static const char* names64[16] = {"rax", "rcx", "rdx",  "rbx", "rsp", "rbp",  "rsi", "rdi",
                                    "r8",  "r9",  "r10",  "r11", "r12", "r13",  "r14", "r15"};
  for (int i = 0; i < 16; ++i) {
    if (n == names32[i] || n == names64[i]) {
      out->index = i;
      out->needs_rex = i >= 8;
      return true;
    }
  }
  return false;
}

class Asm {
 public:
  std::vector<uint8_t> code;
  std::vector<std::string> errors;

  size_t pos() const { return code.size(); }
  void db(uint8_t b) { code.push_back(b); }
  void db(std::initializer_list<uint8_t> bs) {
    code.insert(code.end(), bs.begin(), bs.end());
  }
  void dq(uint64_t v) {
    const size_t at = code.size();
    code.resize(at + 8);
    std::memcpy(code.data() + at, &v, 8);
  }
  void dd(uint32_t v) {
    const size_t at = code.size();
    code.resize(at + 4);
    std::memcpy(code.data() + at, &v, 4);
  }

  // REX：W=1 时用于 64 位操作数
  uint8_t rex(bool w, bool r, bool x, bool b) const {
    return static_cast<uint8_t>(0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0));
  }
  static uint8_t modrm(int mod, int reg, int rm) {
    return static_cast<uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7));
  }

  // ---- 标签与 rel8 回填 ----
  int new_label() { return next_label_++; }
  void bind(int label) { labels_[label] = pos(); }
  // 发一个 rel8 条件跳转（opcode 为 70..7F），目标稍后 bind
  void jcc8(uint8_t opcode, int label) {
    db(opcode);
    const size_t at = pos();
    db(0);
    fixups_.push_back({at, label});
  }
  // 发一个 rel32 条件跳转 0F 8x
  void jcc32(uint8_t cc, int label) {
    db(0x0F);
    db(static_cast<uint8_t>(0x80 | (cc & 0x0F)));
    const size_t at = pos();
    dd(0);
    fixups32_.push_back({at, label});
  }
  void jmp8(int label) {
    db(0xEB);
    const size_t at = pos();
    db(0);
    fixups_.push_back({at, label});
  }

  bool resolve() {
    for (const auto& f : fixups_) {
      auto it = labels_.find(f.label);
      if (it == labels_.end()) {
        errors.push_back("内部错误：未绑定的标签 " + std::to_string(f.label));
        continue;
      }
      const long long delta =
          static_cast<long long>(it->second) - static_cast<long long>(f.at + 1);
      if (delta < -128 || delta > 127) {
        errors.push_back("rel8 跳转超距（跳板过长），标签 " + std::to_string(f.label));
        continue;
      }
      code[f.at] = static_cast<uint8_t>(static_cast<int8_t>(delta));
    }
    for (const auto& f : fixups32_) {
      auto it = labels_.find(f.label);
      if (it == labels_.end()) {
        errors.push_back("内部错误：未绑定的标签 " + std::to_string(f.label));
        continue;
      }
      const long long delta =
          static_cast<long long>(it->second) - static_cast<long long>(f.at + 4);
      const int32_t d32 = static_cast<int32_t>(delta);
      std::memcpy(code.data() + f.at, &d32, 4);
    }
    return errors.empty();
  }

 private:
  std::map<int, size_t> labels_;
  struct Fix { size_t at; int label; };
  std::vector<Fix> fixups_;
  std::vector<Fix> fixups32_;
  int next_label_ = 0;
};

}  // namespace

bool is_valid_register(const std::string& name) {
  Reg32Info info;
  return lookup_reg32(name, &info);
}

bool is_64bit_register_name(const std::string& name) {
  static const char* names64[16] = {"rax", "rcx", "rdx",  "rbx", "rsp", "rbp",  "rsi", "rdi",
                                    "r8",  "r9",  "r10",  "r11", "r12", "r13",  "r14", "r15"};
  for (const char* n : names64)
    if (name == n) return true;
  return false;
}

std::string StubResult::describe() const {
  std::string s;
  char buf[256];
  std::snprintf(buf, sizeof(buf), "stub: %zu 字节, %zu 个需回填的绝对地址\n", code.size(),
                patch_slots.size());
  s += buf;
  for (size_t i = 0; i < code.size(); ++i) {
    std::snprintf(buf, sizeof(buf), "%02x", code[i]);
    s += buf;
    s += (i % 16 == 15) ? "\n" : " ";
  }
  if (!code.empty() && code.size() % 16) s += "\n";
  for (const auto& e : errors) s += "错误: " + e + "\n";
  return s;
}

StubResult build_fileid_stub(const StubConfig& cfg, uint64_t id_table_va, uint32_t count) {
  StubResult r;
  Reg32Info id{}, ret{};
  if (!lookup_reg32(cfg.id_register, &id)) r.errors.push_back("无法识别的 id 寄存器: " + cfg.id_register);
  if (!lookup_reg32(cfg.return_register, &ret))
    r.errors.push_back("无法识别的返回寄存器: " + cfg.return_register);
  if (id.index == 4) r.errors.push_back("不能用 esp/rsp 承载 FileDataID");
  if (id.index == 12) r.errors.push_back("不能用 r12 承载 FileDataID（跳板会破坏它的值）");
  if (id.index == 13) r.errors.push_back("不能用 r13 承载 FileDataID（跳板会破坏它的值）");
  if (count == 0) r.errors.push_back("映射表为空，无需安装跳板");
  if (count > 0x7FFF) r.errors.push_back("映射表过大（>32767 项）");
  if (!r.errors.empty()) return r;

  Asm a;
  const int L_orig = a.new_label();  // 未命中 -> 执行原始指令
  const int L_hit = a.new_label();   // 命中 -> 返回本地路径
  const int L_loop = a.new_label();

  // ---- 1) 无效 id 直接走原文 ----
  if (cfg.signed_check || cfg.zero_check) {
    // test id32, id32 —— reg 与 rm 都是同一个寄存器，r8-r15 需要 REX.R 和 REX.B
    if (id.needs_rex) a.db(a.rex(false, true, false, true));
    a.db({0x85, Asm::modrm(3, id.index, id.index)});
    if (cfg.signed_check) a.jcc8(0x78, L_orig);  // js
    if (cfg.zero_check) {
      // cmp id32, 0   83 /7 ib
      if (id.needs_rex) a.db(a.rex(false, false, false, true));
      a.db({0x83, Asm::modrm(3, 7, id.index), 0x00});
      a.jcc8(0x74, L_orig);  // je
    }
  }

  // ---- 2) 表基址 + 字节偏移 ----
  // mov r10, imm64   49 BA
  a.db({0x49, 0xBA});
  r.patch_slots.push_back({static_cast<int>(a.pos()), "id_table_va"});
  a.dq(id_table_va);
  // xor r11d, r11d   45 31 DB
  a.db({0x45, 0x31, 0xDB});

  // ---- 3) 线性查找 ----
  a.bind(L_loop);
  // cmp id32, dword ptr [r10 + r11]   43 3B /r  (REX.W=0,X=1,B=1)
  //   modrm: mod=00 reg=id rm=100(SIB)；SIB: scale=00 index=011(r11) base=010(r10)
  a.db({static_cast<uint8_t>(0x43 | (id.index >= 8 ? 0x04 : 0x00))});
  a.db(0x3B);
  a.db(Asm::modrm(0, id.index, 4));
  a.db(0x1A);
  a.jcc8(0x74, L_hit);       // je 命中
  a.db({0x49, 0x83, 0xC3, 0x10});  // add r11, 16
  // cmp r11d, count   41 81 FB imm32
  a.db({0x41, 0x81, 0xFB});
  a.dd(count);
  a.jcc8(0x72, L_loop);      // jb 继续（无符号比较，count 已保证 >0）

  // ---- 4) 未命中：执行原始指令 ----
  a.bind(L_orig);
  // jmp qword ptr [rip+0]：FF 25 00000000 + 绝对地址
  a.db({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
  r.patch_slots.push_back({static_cast<int>(a.pos()), "trampoline_va"});
  a.dq(0);

  // ---- 5) 命中：把路径指针放进返回寄存器并返回 ----
  a.bind(L_hit);
  // mov ret64, qword ptr [r10 + r11 + 8]
  {
    const bool w = true;
    const bool rr = ret.index >= 8;
    const bool bb = true;   // base = r10
    const bool xx = true;   // index = r11
    a.db(a.rex(w, rr, xx, bb));
    a.db(0x8B);
    a.db(Asm::modrm(1, ret.index, 4));  // mod=01 -> SIB + disp8
    a.db(0x1A);                          // SIB: index=r11, base=r10
    a.db(0x08);                          // disp8 = 8
  }
  a.db(0xC3);  // ret

  if (!a.resolve()) {
    r.errors = a.errors;
    return r;
  }
  r.code = a.code;
  return r;
}

std::vector<uint8_t> serialize_id_table(
    const std::vector<std::pair<uint64_t, std::string>>& entries,
    std::vector<uint8_t>* string_blob,
    std::vector<std::pair<int, uint32_t>>* string_offsets) {
  std::vector<uint8_t> table(entries.size() * FileIdEntryLayout::kStride, 0);
  std::vector<uint8_t> blob;
  if (string_offsets) string_offsets->clear();

  for (size_t i = 0; i < entries.size(); ++i) {
    const uint64_t id = entries[i].first;
    const std::string& path = entries[i].second;
    uint8_t* row = table.data() + i * FileIdEntryLayout::kStride;
    std::memcpy(row + FileIdEntryLayout::kIdOffset, &id, sizeof(id));
    const uint32_t off = static_cast<uint32_t>(blob.size());
    std::memcpy(row + FileIdEntryLayout::kPathOffset, &off, sizeof(off));
    if (string_offsets) string_offsets->push_back({static_cast<int>(i), off});
    blob.insert(blob.end(), path.begin(), path.end());
    blob.push_back(0);
  }
  if (string_blob) *string_blob = blob;
  return table;
}

}  // namespace wowmod
