// Arctium「自定义文件」机制的逐字节复刻。
//
// 本文件不追求"更好"，只追求【和 Arctium 一模一样】。做法、布局、回填位置、
// 跳转长度全部照抄 src/ModLoader.cs 的 HookClient() + LoadFileMappings()。
//
// 参考实现（MIT）：
//   arctium-all.7z 内为编译产物；机制据
//   Longee-G/Arctium-WoW-Launcher-No-Certificate-Requirements
//     src/ModLoader.cs       LoadFileMappings / AllocateFileMapping / HookClient
//     src/Patterns/Windows.cs  CustomFileIdHook
//     src/Patches/Windows.cs   NoJump = { 0x00, 0x00, 0x00, 0x00 }
//
// 原始序列（照抄）：
//   1. mappings/*.txt 按 "id;path" 解析（ToLowerInvariant，按第一个 ';' 切）
//   2. idAlloc     = VirtualAllocEx(count * (4 + 8))        <- 每条 12 字节
//      stringAlloc = VirtualAllocEx(stringLength)
//      每条: [u32 FileDataID][u64 stringAlloc + 偏移]
//      两块写完都 VirtualProtectEx(PAGE_READONLY)
//   3. 13 字节 hook：  48 B8 <trampoline> FF E0 90
//   4. 跳板 63 字节：
//        +0x00 .. +0x31   50 字节 stub      （js 的 rel32 恒为 42）
//        +0x32 .. +0x3E   13 字节原始指令
//        +0x3F           48 B8 <hook+13> FF E0 90
//   5. NoJump 两条
//
// 与实现无关的注意点：stub 的 js 目标 = 跳板 +50（原始指令），
// 也就是【负 id 时执行原始指令】；命中的路径返回, 不执行原始指令。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace arctium {

// 每条表项 12 字节，与 Arctium 完全一致（不是 16）。
struct EntryLayout {
  static constexpr size_t kId = 0;     // u32
  static constexpr size_t kPath = 4;   // u64（绝对地址）
  static constexpr size_t kStride = 12;
};

// Arctium 的 stub 长度与 hook 长度。
constexpr size_t kStubLen = 50;
constexpr size_t kHookLen = 13;

// Arctium 的 50 字节 stub（Patches 与 ModLoader 里 asm 数组的原样拷贝）。
// 其中三处是占位：
//   偏移 4  : js 的 rel32        -> 恒为 42（跳到 +50 的原始指令）
//   偏移 12 : idAlloc 绝对地址   -> movabs r9, <u64>
//   偏移 35 : count              -> cmp eax, <u32>
std::vector<uint8_t> arctium_stub_template();

// 按 Arctium 的三处回填生成完整 stub。
//   id_alloc_va  写入偏移 12
//   count        写入偏移 35
//   js_rel32     写入偏移 4（默认 42）
std::vector<uint8_t> build_arctium_stub(uint64_t id_alloc_va, uint32_t count,
                                        int32_t js_rel32 = 42);

// 13 字节绝对跳转：48 B8 <u64> FF E0 90
std::vector<uint8_t> build_hook_jump(uint64_t dst);

// 把 (id, path) 列表序列化成 Arctium 的表 + 字符串块。
//   table        : count * 12 字节
//   strings      : 所有路径连在一起（UTF-8，\\ -> /，小写，'+1' 结尾 NUL）
// 路径字段先写【字符串块内偏移】，由调用方在知道 stringAlloc 绝对地址后
// 用 patch_string_addresses() 改写成绝对地址（和 Arctium 的
// AllocateFileMapping 里 Buffer.BlockCopy(stringAlloc + stringPos) 等价）。
struct SerializedMappings {
  std::vector<uint8_t> table;
  std::vector<uint8_t> strings;
  size_t count = 0;
  std::vector<uint32_t> offsets;   // 每条在 strings 内的偏移
};

SerializedMappings serialize_arctium_mappings(
    const std::vector<std::pair<uint64_t, std::string>>& entries);

// 把 table 里每条路径字段从"字符串块内偏移"改成"绝对地址"。
void patch_string_addresses(SerializedMappings* m, uint64_t string_alloc_va);

}  // namespace arctium
}  // namespace wowmod
