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
