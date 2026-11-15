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
};

struct AntiCrashPlan {
  bool ok = false;
  std::string error;
  std::vector<AntiCrashPatch> patches;
  size_t integrity_hits = 0;     // Integrity + Integrity2 命中数
  size_t remap_hits = 0;         // Remap 特征码命中数
  size_t remap_jump_patches = 0; // 由 remap 推导出的跳转补丁数
  std::vector<std::string> notes;
};

// 给定映像字节与基址，算出所有 anti-crash 补丁。纯函数，不碰进程。
AntiCrashPlan plan_anti_crash_from_image(const std::vector<uint8_t>& image, uint64_t image_base);

// Arctium 的三条特征码（Patterns/Windows.cs 原样）。供测试与文档引用。
const char* anticrash_integrity_pattern();
const char* anticrash_integrity2_pattern();
const char* anticrash_remap_pattern();
// Arctium Patches/Windows.cs: Integrity = { 0xC2, 0x00, 0x00 }
const uint8_t* anticrash_integrity_bytes(size_t* len);

}  // namespace wowmod
