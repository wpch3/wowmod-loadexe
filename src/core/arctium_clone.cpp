// Arctium 机制的逐字节复刻实现。见 arctium_clone.hpp。
// SPDX-License-Identifier: MIT
#include "windows/arctium_clone.hpp"

#include <algorithm>
#include <cstring>

namespace wowmod {
namespace arctium {
namespace {

// Arctium src/ModLoader.cs HookClient() 里的 asm 数组，原样拷贝。
//   85 D2                          test edx, edx
//   0F 88 72 AF FF FF              js   <原函数 +0>        (rel32 会回填)
//   33 C0                          xor  eax, eax
//   49 B9 22.. 11..                movabs r9, <idAlloc>   (回填)
//   8D 0C 40                       lea  ecx, [rax+rax*2]
//   C1 E1 02                       shl  ecx, 2
//   42 39 14 09                    cmp  dword [rcx+r9], edx
//   74 0C                          je   +0x0e
//   FF C0                          inc  eax
//   3D EF BE AD DE                 cmp  eax, <count>      (回填)
//   72 EB                          jb   -0x15
//   33 C0                          xor  eax, eax
//   C3                             ret
//   4A 8B 44 09 04                 mov  rax, [rcx+r9+4]
//   C3                             ret
const uint8_t kStub[50] = {0x85, 0xD2, 0x0F, 0x88, 0x72, 0xAF, 0xFF, 0xFF, 0x33, 0xC0,
                           0x49, 0xB9, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11,
                           0x8D, 0x0C, 0x40, 0xC1, 0xE1, 0x02, 0x42, 0x39, 0x14, 0x09,
                           0x74, 0x0C, 0xFF, 0xC0, 0x3D, 0xEF, 0xBE, 0xAD, 0xDE, 0x72,
                           0xEB, 0x33, 0xC0, 0xC3, 0x4A, 0x8B, 0x44, 0x09, 0x04, 0xC3};

}  // namespace

std::vector<uint8_t> arctium_stub_template() {
  return std::vector<uint8_t>(kStub, kStub + sizeof(kStub));
}

std::vector<uint8_t> build_arctium_stub(uint64_t id_alloc_va, uint32_t count,
                                        int32_t js_rel32) {
  std::vector<uint8_t> s = arctium_stub_template();
  std::memcpy(s.data() + 4, &js_rel32, 4);       // js 的 rel32（恒为 42）
  std::memcpy(s.data() + 12, &id_alloc_va, 8);   // movabs r9, idAlloc
  std::memcpy(s.data() + 35, &count, 4);         // cmp eax, count
  return s;
}

std::vector<uint8_t> build_hook_jump(uint64_t dst) {
  // 48 B8 <u64> FF E0 90   —— Arctium 的 hookInstructions 原样
  std::vector<uint8_t> j = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0, 0x90};
  std::memcpy(j.data() + 2, &dst, 8);
  return j;
}

std::string arctium_stored_path(const std::string& files_dir_abs,
                                const std::string& relative_path) {
  // 已经是绝对路径（带盘符或 UNC）就原样返回，避免拼成两遍。
  const std::string rel = relative_path;
  const bool abs = (rel.size() >= 2 && rel[1] == ':') ||
                   (rel.size() >= 2 && rel[0] == '\\' && rel[1] == '\\') ||
                   (rel.size() >= 1 && rel[0] == '/');
  std::string base = files_dir_abs;
  // 统一成正斜杠：Arctium 存的是 .NET 的 Path 组合结果，Windows 上原本是
  // 反斜杠；但客户端对两种都接受，而正斜杠在报告/日志里不会引出转义问题。
  std::replace(base.begin(), base.end(), '\\', '/');
  while (!base.empty() && base.back() == '/') base.pop_back();
  if (abs) return rel;
  std::string out = base + "/" + rel;
  // 相对路径里可能含 ./ 或重复斜杠，规整一次
  std::string norm;
  norm.reserve(out.size());
  for (size_t i = 0; i < out.size(); ++i) {
    if (out[i] == '/' && !norm.empty() && norm.back() == '/') continue;
    norm.push_back(out[i]);
  }
  return norm;
}

SerializedMappings serialize_arctium_mappings(const std::vector<MappingEntry>& entries) {
  SerializedMappings out;
  out.count = entries.size();
  out.table.assign(entries.size() * EntryLayout::kStride, 0);
  out.offsets.reserve(entries.size());

  for (size_t i = 0; i < entries.size(); ++i) {
    const uint64_t id = entries[i].file_id;
    uint8_t* row = out.table.data() + i * EntryLayout::kStride;

    // Arctium: BitConverter.GetBytes(id) 是 u32
    const uint32_t id32 = static_cast<uint32_t>(id);
    std::memcpy(row + EntryLayout::kId, &id32, 4);

    // 字符串原样写入。
    //
    // 注意：**不要**小写、不要改斜杠。
    // Arctium 存的是它在 files 目录里枚举出来的真实文件名，Windows
    // 不区分大小写，所以大小写不影响打开；而这里再去 lower 一次，
    // 反倒会让报告里显示的名字和磁盘上的不一致，排查时更费劲。
    // （我们过去是 lower + 反斜杠转正斜杠，两处都改掉了。）
    const std::string& p = entries[i].string_to_store;

    const uint32_t off = static_cast<uint32_t>(out.strings.size());
    out.offsets.push_back(off);

    // 先写字符串块内偏移，后面 patch_string_addresses 改成绝对地址
    std::memcpy(row + EntryLayout::kPath, &off, 4);

    out.strings.insert(out.strings.end(), p.begin(), p.end());
    out.strings.push_back(0);   // Arctium: pathBytes 含结尾 NUL，stringLength += len+1
  }
  return out;
}

SerializedMappings serialize_arctium_mappings(
    const std::vector<std::pair<uint64_t, std::string>>& entries) {
  std::vector<MappingEntry> conv;
  conv.reserve(entries.size());
  for (const auto& e : entries) {
    MappingEntry m;
    m.file_id = e.first;
    m.string_to_store = e.second;
    conv.push_back(std::move(m));
  }
  return serialize_arctium_mappings(conv);
}

void patch_string_addresses(SerializedMappings* m, uint64_t string_alloc_va) {
  if (!m) return;
  for (size_t i = 0; i < m->count; ++i) {
    uint8_t* row = m->table.data() + i * EntryLayout::kStride;
    uint32_t off = 0;
    std::memcpy(&off, row + EntryLayout::kPath, 4);
    const uint64_t abs = string_alloc_va + off;
    std::memcpy(row + EntryLayout::kPath, &abs, 8);
  }
}

}  // namespace arctium
}  // namespace wowmod
