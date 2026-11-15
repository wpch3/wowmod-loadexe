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
//   js_rel32     写入偏移 4（恒为 42）
//
// 42 从哪来（照 Arctium ModLoader.cs HookClient 的公式）：
//   rel32 = asm.Length - 2 - 6 = 50 - 8 = 42
// js 指令本身在 +2、长 6 字节，下一条指令地址是 stub+8，加 42 = stub+50，
// 正好是紧跟在 stub 之后的【原始指令第 0 字节】。也就是说负 id（Arctium
// 用负数表示"这次不走自定义文件"）会正确落回原函数继续执行。
// 注意这里只看 stub 自己的长度，与跳板后面接什么无关 —— 所以不需要调整。
std::vector<uint8_t> build_arctium_stub(uint64_t id_alloc_va, uint32_t count,
                                        int32_t js_rel32 = 42);

// ---- 带观测点的 stub ----
//
// 【为什么必须有它】
//
// 纯 Arctium 的 50 字节 stub 是"哑"的：它查表、返回路径或 0，但我们
// 从外部完全无法知道它被调用过几次、命中几次。于是"装好了但不生效"
// 完全无法定位 —— 是 hook 没生效？id 对不上？还是客户端根本没用返回值？
// 这三种情况在外部表现一模一样。
//
// 这里在 stub 里加两个计数：
//   call_counter  (u64): 每进入 stub 一次 +1
//   hit_counter   (u64): 每命中一次 +1
// 两个地址由调用方分配并写入。功能行为与 Arctium 完全一致，只是多了计数。
std::vector<uint8_t> build_instrumented_stub(uint64_t id_alloc_va, uint32_t count,
                                             uint64_t call_counter_va,
                                             uint64_t hit_counter_va,
                                             int32_t js_rel32);

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

// 一条映射：id + 要写进字符串块的【那条字符串】。
//
// 关键：Arctium（ModLoader.cs GetFileMappingData）写进字符串块的
// 不是游戏内相对路径，而是 **files 目录下的磁盘绝对路径**：
//     var pathBytes = Encoding.UTF8.GetBytes(f);            // f = 绝对路径
//     ...
//     loadedMappings.Add((BitConverter.GetBytes(id), pathBytes, stringLength));
// 它只用相对路径去 mappings 里【查 id】（mappings[path]），
// 查完之后存下来的是 f 本身。
//
// 我们之前存的是相对路径 —— 于是 stub 返回
//     "character/bloodelf/female/xxx.blp"
// 而客户端拿到的是一个路径指针，会把它当文件去打开；相对路径相对的是
// 客户端进程的当前目录（游戏根），那里没有这个文件。表现就是
// 「跳板装了、id 也命中、但模型/贴图一点变化都没有」。
//
// 文件格式对 .blp / .m2 / .skin 一视同仁（都由同一条查表路径返回），
// 但只要返回值不是可打开的磁盘路径，任何类型的模组都不会生效。
struct MappingEntry {
  uint64_t file_id = 0;
  std::string string_to_store;   // 写进字符串块的内容（Arctium: 绝对路径）
};

SerializedMappings serialize_arctium_mappings(const std::vector<MappingEntry>& entries);

// 兼容旧签名：把 (id, stored_string) 对转成 MappingEntry。
SerializedMappings serialize_arctium_mappings(
    const std::vector<std::pair<uint64_t, std::string>>& entries);

// 按 Arctium 的方式算出「写进字符串块的绝对路径」。
//
// Arctium 直接在 files 目录里枚举文件，f 天然是绝对路径。
// 我们从 mappings 声明了相对路径，所以必须由
//     files 目录的绝对路径 + 相对路径
// 显式拼出来，否则写进去的还是相对路径。
//
// files_dir_abs : files 目录的绝对路径（例如 D:/.../wowmod/files）
// relative_path : mappings 里写的游戏相对路径
std::string arctium_stored_path(const std::string& files_dir_abs, const std::string& relative_path);

// 把 table 里每条路径字段从"字符串块内偏移"改成"绝对地址"。
void patch_string_addresses(SerializedMappings* m, uint64_t string_alloc_va);

}  // namespace arctium
}  // namespace wowmod
