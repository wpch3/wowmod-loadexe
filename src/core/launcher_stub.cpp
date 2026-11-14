// PE 解析 + 早期执行跳板规划（.pdata 覆盖技术）。
// SPDX-License-Identifier: MIT
#include "wowmod/launcher_stub.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace wowmod {

namespace {

uint16_t rd16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
uint32_t rd32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

}  // namespace

size_t PeLayout::rva_to_offset(uint32_t rva) const {
  for (const auto& s : sections) {
    if (rva >= s.va && rva < s.va + std::max(s.vsize, s.raw_size)) {
      const uint32_t delta = rva - s.va;
      if (delta < s.raw_size) return static_cast<size_t>(s.raw_ptr) + delta;
      return SIZE_MAX;  // 落在未初始化部分（内存里有、文件里没有）
    }
  }
  return SIZE_MAX;
}

const PeLayout::Section* PeLayout::section_of(uint32_t rva) const {
  for (const auto& s : sections)
    if (rva >= s.va && rva < s.va + std::max(s.vsize, s.raw_size)) return &s;
  return nullptr;
}

PeLayout parse_pe_file(const std::vector<uint8_t>& f) {
  PeLayout pe;
  if (f.size() < 0x100) {
    pe.error = "文件过小";
    return pe;
  }
  if (f[0] != 'M' || f[1] != 'Z') {
    pe.error = "不是 MZ";
    return pe;
  }
  const uint32_t lfanew = rd32(f.data() + 0x3C);
  if (lfanew + 0x40 > f.size() || rd32(f.data() + lfanew) != 0x00004550u) {
    pe.error = "不是 PE";
    return pe;
  }
  const uint16_t machine = rd16(f.data() + lfanew + 4);
  const uint16_t nsec = rd16(f.data() + lfanew + 6);
  const uint16_t optsz = rd16(f.data() + lfanew + 20);
  const size_t opt = lfanew + 24;
  if (opt + 2 > f.size()) {
    pe.error = "可选头缺失";
    return pe;
  }
  const uint16_t magic = rd16(f.data() + opt);
  if (magic != 0x20B) {
    pe.error = machine == 0x14C ? "这是 32 位 PE（需要 x64）" : "不是 PE32+（需要 x64）";
    return pe;
  }
  pe.image_base = rd64(f.data() + opt + 24);
  pe.size_of_image = rd32(f.data() + opt + 56);
  pe.entry_rva = rd32(f.data() + opt + 16);

  const size_t sec_off = opt + optsz;
  for (uint16_t i = 0; i < nsec; ++i) {
    const size_t o = sec_off + i * 40;
    if (o + 40 > f.size()) break;
    PeLayout::Section s;
    char name[9] = {0};
    std::memcpy(name, f.data() + o, 8);
    s.name = name;
    s.vsize = rd32(f.data() + o + 8);
    s.va = rd32(f.data() + o + 12);
    s.raw_size = rd32(f.data() + o + 16);
    s.raw_ptr = rd32(f.data() + o + 20);
    s.characteristics = rd32(f.data() + o + 36);
    pe.sections.push_back(s);
  }

  // 数据目录
  const uint32_t ndirs = rd32(f.data() + opt + 108);
  auto dir = [&](int idx, uint32_t* va, uint32_t* size) {
    const size_t o = opt + 112 + idx * 8;
    if (o + 8 > f.size() || idx >= static_cast<int>(ndirs)) return false;
    *va = rd32(f.data() + o);
    *size = rd32(f.data() + o + 4);
    return true;
  };
  // 异常表（.pdata）= 目录 3，基址重定位 = 目录 5
  uint32_t pdata_va = 0, pdata_size = 0;
  if (dir(3, &pdata_va, &pdata_size) && pdata_size >= 12) {
    const size_t off = pe.rva_to_offset(pdata_va);
    if (off != SIZE_MAX) {
      pe.pdata_section_va = pdata_va;
      pe.pdata_entries_off = static_cast<uint32_t>(off);
      const uint32_t n = pdata_size / 12;
      for (uint32_t i = 0; i < n && off + i * 12 + 12 <= f.size(); ++i) {
        PdataEntry e;
        e.begin_rva = rd32(f.data() + off + i * 12);
        e.end_rva = rd32(f.data() + off + i * 12 + 4);
        e.unwind_rva = rd32(f.data() + off + i * 12 + 8);
        pe.pdata.push_back(e);
      }
      std::sort(pe.pdata.begin(), pe.pdata.end(),
                [](const PdataEntry& a, const PdataEntry& b) { return a.begin_rva < b.begin_rva; });
    }
  }
  uint32_t reloc_va = 0, reloc_size = 0;
  if (dir(5, &reloc_va, &reloc_size) && reloc_size >= 8) {
    const size_t off = pe.rva_to_offset(reloc_va);
    if (off != SIZE_MAX) {
      size_t p = off;
      const size_t end = std::min(f.size(), off + reloc_size);
      while (p + 8 <= end) {
        const uint32_t page_va = rd32(f.data() + p);
        const uint32_t block_size = rd32(f.data() + p + 4);
        if (block_size < 8 || p + block_size > end) break;
        const uint32_t n = (block_size - 8) / 2;
        for (uint32_t i = 0; i < n; ++i) {
          const uint16_t e = rd16(f.data() + p + 8 + i * 2);
          RelocInfo ri;
          ri.type = static_cast<uint16_t>(e >> 12);
          ri.rva = page_va + (e & 0x0FFF);
          pe.relocs.push_back(ri);
        }
        p += block_size;
      }
    }
  }

  pe.ok = true;
  return pe;
}

StubPlan plan_launcher_stub(const PeLayout& pe, const std::vector<uint8_t>& file, size_t min_cave,
                            bool require_no_reloc) {
  StubPlan plan;
  if (!pe.ok) {
    plan.reason = "PE 无效: " + pe.error;
    return plan;
  }
  if (pe.pdata.empty()) {
    plan.reason = "找不到 .pdata 异常表（可能被剥掉，或本身不是 x64 客户端）";
    return plan;
  }

  auto has_reloc_in = [&](uint32_t from, uint32_t to) {
    if (!require_no_reloc) return false;
    for (const auto& r : pe.relocs)
      if (r.rva >= from && r.rva < to) return true;
    return false;
  };
  (void)has_reloc_in;

  // 找一条 RUNTIME_FUNCTION：它前面有 >= min_cave 的填充（0xCC/0x90/0x00），
  // 且填充区与代码区在同一可执行区段内。
  for (size_t i = 0; i < pe.pdata.size(); ++i) {
    const PdataEntry& e = pe.pdata[i];
    if (e.begin_rva == 0 || e.end_rva <= e.begin_rva) continue;
    const size_t off_begin = pe.rva_to_offset(e.begin_rva);
    if (off_begin == SIZE_MAX || off_begin == 0) continue;
    const auto* sec = pe.section_of(e.begin_rva);
    if (!sec || !sec->executable()) continue;

    // 向前统计填充
    size_t run = 0;
    while (run < 4096 && off_begin > run) {
      const uint8_t b = file[off_begin - run - 1];
      if (b == 0xCC || b == 0x90 || b == 0x00) ++run;
      else break;
    }
    if (run < min_cave) continue;
    // 只需要 min_cave 字节：紧贴函数入口取，尽量少侵占填充区，
    // 避免和别的数据/其他 RUNTIME_FUNCTION 冲突。按 16 字节对齐。
    size_t need = min_cave;
    if (need % 16) need += 16 - (need % 16);
    if (need > run) need = run;
    const size_t back = need;

    // 填充区不能跨出区段
    const uint32_t cave_rva = e.begin_rva - static_cast<uint32_t>(back);
    if (cave_rva < sec->va) continue;
    // 填充区不能含被重定位的字段（否则改写会被加载器再次修正）
    if (has_reloc_in(cave_rva, e.begin_rva)) continue;
    // 填充区不能和别的 RUNTIME_FUNCTION 重叠（否则会破坏其他异常处理）
    bool overlaps = false;
    for (const auto& other : pe.pdata) {
      if (&other == &e) continue;
      if (other.begin_rva < e.begin_rva && other.end_rva > cave_rva) { overlaps = true; break; }
    }
    if (overlaps) continue;

    plan.ok = true;
    plan.entry = e;
    plan.begin_field_rva = static_cast<uint32_t>(pe.pdata_entries_off) +
                           static_cast<uint32_t>(i * 12);  // 注意：这是【文件偏移】，不是 RVA
    // BeginAddress 字段在文件中的绝对偏移不方便跨区段表示，这里直接给文件偏移
    plan.cave_rva = cave_rva;
    plan.cave_size = back;
    plan.reason = "在 " + std::string(sec->name) + " 找到 " + std::to_string(back) +
                  " 字节填充（" + std::to_string(cave_rva) + " - " +
                  std::to_string(e.begin_rva) + "）";
    return plan;
  }

  plan.reason = "exe 中没有找到足够大的、紧邻函数入口的填充区（这条路线对当前客户端不适用）";
  return plan;
}

std::vector<uint8_t> build_launcher_stub_code(const LauncherStubConfig& cfg) {
  // 生成结构：
  //   pushfq
  //   push rax..r15（15 个寄存器：除 rsp）
  //   mov rcx, <stub_va>            ; payload 的参数：自定位
  //   mov rax, <payload_va>
  //   call rax
  //   pop  r15..rax（逆序）
  //   popfq
  //   <被顶替的原始序言字节>
  //   mov rax, <真实入口>
  //   jmp rax
  //
  // 注意：这里刻意不修改栈以外的内存，payload 不在栈上分配任何东西的约定由调用方保证。
  std::vector<uint8_t> c;
  auto db = [&](std::initializer_list<uint8_t> bs) { c.insert(c.end(), bs.begin(), bs.end()); };
  auto dq = [&](uint64_t v) {
    const size_t at = c.size();
    c.resize(at + 8);
    std::memcpy(c.data() + at, &v, 8);
  };

  db({0x9C});  // pushfq
  for (int r : {0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
    if (r < 8) db({static_cast<uint8_t>(0x50 + r)});
    else db({0x41, static_cast<uint8_t>(0x50 + (r - 8))});
  }

  // mov rcx, imm64
  db({0x48, 0xB9});
  dq(cfg.stub_va);
  // mov rax, imm64 ; call rax
  db({0x48, 0xB8});
  dq(cfg.payload_va);
  db({0xFF, 0xD0});

  for (int r : {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 3, 2, 1, 0}) {
    if (r < 8) db({static_cast<uint8_t>(0x58 + r)});
    else db({0x41, static_cast<uint8_t>(0x58 + (r - 8))});
  }
  db({0x9D});  // popfq

  c.insert(c.end(), cfg.stolen_prologue.begin(), cfg.stolen_prologue.end());

  // 跳回真实入口
  const uint64_t back = cfg.stub_va + c.size() + 12;
  db({0x48, 0xB8});
  dq(back);
  db({0xFF, 0xE0});
  return c;
}

std::vector<uint8_t> build_launcher_stub(uint64_t payload_va, uint64_t stub_va,
                                         const std::vector<uint8_t>& stolen_prologue) {
  LauncherStubConfig cfg;
  cfg.payload_va = payload_va;
  cfg.stub_va = stub_va;
  cfg.stolen_prologue = stolen_prologue;
  return build_launcher_stub_code(cfg);
}

}  // namespace wowmod
