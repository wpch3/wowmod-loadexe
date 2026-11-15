// Arctium PrepareAntiCrash 的【纯逻辑】部分。
//
// 为什么单独放在 core：这部分不需要 windows.h，可以离线用合成映像验证。
// 而它正是最容易写错、写错了就崩客户端的地方（偏移算错一个字节 =
// 跳到指令中间 = 立刻 EXCEPTION_INTERNAL_ERROR）。
//
// 机制说明见 src/windows/anticrash.hpp。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {

struct AntiCrashPatch {
  uint64_t va = 0;
  std::vector<uint8_t> bytes;
  std::string name;   // "Integrity0" / "Integrity1" / "Jump<va>" / "ShortJump<va>"
                      // / "CertBundle" / "CertCommonName" / "CertChain" / "CertCheck"
  bool cert = false;  // true = 证书相关（连私有服务器才需要），默认不装
};

struct AntiCrashPlan {
  bool ok = false;
  std::string error;
  std::vector<AntiCrashPatch> patches;
  size_t integrity_hits = 0;     // Integrity + Integrity2 命中数
  size_t remap_hits = 0;         // Remap 特征码命中数
  size_t remap_jump_patches = 0; // 由 remap 推导出的跳转补丁数
  size_t cert_patches = 0;       // 证书补丁数（CertBundle/CertCommonName/CertChain/CertCheck）
  std::vector<std::string> notes;
};

// 给定映像字节与基址，算出所有 anti-crash 补丁。纯函数，不碰进程。
//
// cert_patches: 是否同时算证书补丁。
//   默认 false —— 模组加载完全不需要它们，装了只是多改几个字节。
//   只有连私有服务器（需要客户端不校验对方证书）时才需要。
AntiCrashPlan plan_anti_crash_from_image(const std::vector<uint8_t>& image, uint64_t image_base,
                                         bool cert_patches = false);

// ---- 节保护属性（重映射后必须按节还原，纯函数便于单测）----
//
// 这是"重映射把客户端弄死"的根因：上游 RemapAndPatch 整块映射成
// PAGE_EXECUTE_READ，然后只对 BaseAddress 检查 AllocationProtect。
// 对 Arctium 的场景够用（它只关心代码页），但整块 RX 会让 .data 段
// 变成只读 —— 客户端一写全局变量就访问违例，连窗口都不出。
// 这里按 PE 节的真实属性逐段设保护，与系统加载器一致。
//
// 输入是节的标志位，输出 Windows 保护常量。为避免把 windows.h
// 拖进 core，用数值常量（值与原义一一对应）。
constexpr uint32_t kProtNoAccess = 0x01;
constexpr uint32_t kProtReadOnly = 0x02;
constexpr uint32_t kProtReadWrite = 0x04;
constexpr uint32_t kProtExecute = 0x10;
constexpr uint32_t kProtExecuteRead = 0x20;
constexpr uint32_t kProtExecuteReadWrite = 0x40;

struct SectionProtSpec {
  uint64_t rva = 0;
  uint64_t size = 0;
  bool executable = false;
  bool writable = false;
  bool readable = false;
};

// 由节标志推出保护常量。
uint32_t section_protection(bool executable, bool writable, bool readable);

// 把节列表按页对齐展开成「每个页一段」的保护表，便于逐段设置。
// 重叠时后者覆盖前者（调用方应按 RVA 升序传入）。
struct PageProt {
  uint64_t offset = 0;   // 相对映像基址
  uint64_t size = 0;     // 字节数（已页对齐）
  uint32_t protect = 0;
};
std::vector<PageProt> build_page_protections(const std::vector<SectionProtSpec>& sections,
                                             uint64_t image_size);

// ---- 把补丁应用到本地快照（RemapAndPatch 的核心，纯函数便于单测）----
//
// 上游 ApplyPatches(remap: true)：
//     for (var i = 0; i < patch.Length; i++) Data[address + i] = patch[i];
// 其中 address 是【相对映像基址的偏移】。这里用 VA 形式，内部换算。
//
// 返回实际应用成功的条数。以下情况跳过（不报错，与上游一致）：
//   * 补丁完全落在快照之外
//   * 补丁跨越快照末尾
// 部分覆盖会被【拒绝】（上游会越界写，我们不复制这个缺陷）。
size_t apply_patches_to_snapshot(std::vector<uint8_t>* snapshot, uint64_t image_base,
                                 const std::vector<AntiCrashPatch>& patches);

// Arctium 的四条证书特征码与对应补丁（Patterns/Windows.cs + Patches/Windows.cs 原样）。
struct CertPatchSpec {
  const char* name;
  const char* pattern;
  int offset;                  // 命中点之后第几个字节开始写
  std::vector<uint8_t> bytes;  // 要写的内容
};
const std::vector<CertPatchSpec>& cert_patch_specs();

// Arctium 的三条特征码（Patterns/Windows.cs 原样）。供测试与文档引用。
const char* anticrash_integrity_pattern();
const char* anticrash_integrity2_pattern();
const char* anticrash_remap_pattern();
// Arctium Patches/Windows.cs: Integrity = { 0xC2, 0x00, 0x00 }
const uint8_t* anticrash_integrity_bytes(size_t* len);

}  // namespace wowmod
