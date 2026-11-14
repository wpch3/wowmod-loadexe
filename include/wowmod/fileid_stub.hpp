// FileDataID -> 本地文件 的 x64 跳板代码生成器（纯数据/字节层，可在 Linux 上单元测试）。
//
// 设计目标：把「版本知识」全部变成参数。
// 公开的 Arctium 参照实现把这两件事写死：
//     * FileDataID 一定在 EDX          （9.x/10.x 的约定）
//     * 命中时一定把路径指针放 RAX 返回
// 换到 12.0.7 之后这两条都不成立，于是要么 hook 不上，要么把垃圾指针当路径返回直接崩。
//
// 本生成器把「id 在哪个寄存器」「命中时怎么返回」做成参数：
//     idRegister : rcx / rdx / r8 / r9 / rsi / rdi / rbx / rax ...
//     hitMode    : return_path      —— 命中时把路径指针放进返回寄存器并 ret
//                  call_original   —— 命中时调用原函数并把结果写回（hook 点不适合 ret）
//     valueIsWide: id 该寄存器里是 32 位还是 64 位（高 32 位可能脏）
//
// 生成的字节布局（全部相对寻址，位置无关，不含绝对地址，不含重定位）：
//   [符号检查: 有符号/0 直接跳原文]
//   [保存易失寄存器]
//   [表查找循环: cmp [idTable + i*12 + 0], reg32 / jne next]
//   [命中: mov rax, [idTable + i*12 + 4] / 恢复 / ret]
//   [未命中: 恢复 / jmp trampoline]
//   [数据: idTable 指针 / count]
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wowmod {

// id 在目标进程内存中的表项：8 字节 id + 8 字节路径指针 = 16 字节。
// （参照实现用的是 4+8=12 的对齐很差的布局；16 字节对 CPU 更友好，也便于以后扩展到 64 位 id）
struct FileIdEntryLayout {
  static constexpr size_t kIdOffset = 0;
  static constexpr size_t kPathOffset = 8;
  static constexpr size_t kStride = 16;
};

struct StubConfig {
  std::string id_register = "rdx";  // 承载 FileDataID 的寄存器
  std::string return_register = "rax";  // 命中时把路径指针放到哪个寄存器
  bool signed_check = true;   // id 最高位为 1（负数）时视为特殊值，直接跳原文
  bool zero_check = true;     // id == 0 视为无效，直接跳原文
};

struct StubResult {
  std::vector<uint8_t> code;
  std::vector<std::string> errors;
  std::vector<std::pair<int, std::string>> patch_slots;  // code 内偏移 -> 需要填入的绝对值
  bool ok() const { return errors.empty() && !code.empty(); }
  std::string describe() const;
};

#include <map>

// 校验寄存器名。
bool is_valid_register(const std::string& name);
bool is_64bit_register_name(const std::string& name);

// 生成跳板。idTableVa 是目标进程里表项的绝对地址（表必须是 16 字节步长）。
// count 为表项数量（最多 0x7FFF，避免 imm32 负值问题）。
StubResult build_fileid_stub(const StubConfig& cfg, uint64_t id_table_va, uint32_t count);

// 把 id 表序列化成可以直接写进目标进程的字节。
std::vector<uint8_t> serialize_id_table(const std::vector<std::pair<uint64_t, std::string>>& entries,
                                       std::vector<uint8_t>* string_blob,
                                       std::vector<std::pair<int, uint32_t>>* string_offsets);

}  // namespace wowmod
