// Arctium PrepareAntiCrash 的纯逻辑实现。见 include/wowmod/anticrash_plan.hpp。
// SPDX-License-Identifier: MIT
#include "wowmod/anticrash_plan.hpp"

#include <algorithm>
#include <cstring>
#include <set>

#include "wowmod/hooks.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace {

// Arctium：Patches/Windows.cs Integrity = { 0xC2, 0x00, 0x00 }  (= ret 0)
const uint8_t kIntegrityPatch[3] = {0xC2, 0x00, 0x00};

// Arctium 的三个特征码（Patterns/Windows.cs，逐字节照抄）。
//   直接写成 IDA 风格字符串，由现有的 Pattern 解析器处理。
const char* kIntegrityPattern =
    "44 89 ?? 24 ?? 44 89 ?? 24 ?? 89 ?? 24 ?? 48 89 ?? 24 ?? 53 56 57";
const char* kIntegrity2Pattern =
    "44 89 ?? 24 ?? 44 89 ?? 24 ?? 89 ?? 24 ?? 48 89 ?? 24 ?? 53 57";
const char* kRemapPattern = "48 ?? ?? 1E 0F 83";

// 这三个判据必须与 Arctium（WinMemory.cs）逐字节一致：
//
//     IsJump(i)             : p[i]==0x0F && p[i+1] in 0x80..0x8F    (Jcc rel32, 6B)
//     IsShortJump(i)        : p[i] in 0x70..0x7E                     (Jcc rel8, 2B)
//     IsUnconditionalJump(i): p[i]==0xE9 || p[i]==0xEB
//
// 注意 0x7F 不算短跳转、0xEB 也不算 —— Arctium 原文就是 `< 0x7F`。
// 写宽一格会让 EB 形态的 jmp rel8 被当成 Jcc，进而算错 rel32，
// 这种"顺手改好一点"正是不能做的地方。
bool is_jump(const uint8_t* p, size_t n, size_t i) {
  return i + 5 < n && p[i] == 0x0F && p[i + 1] >= 0x80 && p[i + 1] <= 0x8F;
}
bool is_short_jump(const uint8_t* p, size_t n, size_t i) {
  return i + 1 < n && p[i] >= 0x70 && p[i] < 0x7F;
}
bool is_unconditional_jump(const uint8_t* p, size_t n, size_t i) {
  return i < n && (p[i] == 0xE9 || p[i] == 0xEB);
}

}  // namespace

// 允许命名空间内的常量被下面的访问函数使用

AntiCrashPlan plan_anti_crash_from_image(const std::vector<uint8_t>& image, uint64_t image_base) {
  AntiCrashPlan plan;
  const size_t n = image.size();
  if (n < 0x1000) {
    plan.error = "映像太小，不做 anti-crash 规划";
    return plan;
  }
  const uint8_t* d = image.data();

  // ---- 1. 完整性校验函数：命中处写 ret 0 ----
  struct { const char* name; const char* pat; } sigs[] = {
      {"Integrity", kIntegrityPattern}, {"Integrity2", kIntegrity2Pattern}};
  for (const auto& s : sigs) {
    std::string perr;
    const Pattern pat = Pattern::parse(s.pat, &perr);
    if (!pat.valid()) {
      plan.notes.push_back(std::string(s.name) + ": 特征码解析失败 " + perr);
      continue;
    }
    const auto offs = pat.find_all(image);
    for (size_t off : offs) {
      // 必须有 3 个字节可写
      if (off + sizeof(kIntegrityPatch) > n) continue;
      AntiCrashPatch p;
      p.va = image_base + off;
      p.bytes.assign(kIntegrityPatch, kIntegrityPatch + sizeof(kIntegrityPatch));
      p.name = std::string(s.name) + "@" + std::to_string(plan.integrity_hits);
      plan.patches.push_back(std::move(p));
      ++plan.integrity_hits;
    }
  }

  // ---- 2. remap 校验：找出所有「跳向真实代码」的跳转，各挪 1 字节 ----
  {
    std::string perr;
    const Pattern remap = Pattern::parse(kRemapPattern, &perr);
    if (!remap.valid()) {
      plan.notes.push_back("Remap: 特征码解析失败 " + perr);
    } else {
      const auto offs = remap.find_all(image);
      plan.remap_hits = offs.size();
      size_t last_address = 0;
      std::set<uint64_t> already;   // 同一地址只打一次（Arctium 用字典去重）

      for (size_t a : offs) {
        const size_t instruction_start = a + 4;
        if (instruction_start + 6 > n) continue;
        const uint8_t* ins = d + instruction_start;

        // 无条件跳转跳过（Arctium: if (IsUnconditionalJump(instructions)) continue;）
        if (is_unconditional_jump(ins, 6, 0)) continue;

        int64_t operand_value = 0;
        if (is_short_jump(ins, 6, 0)) {
          operand_value = static_cast<int64_t>(ins[1]) + 2;
        } else if (is_jump(ins, 6, 0)) {
          int32_t rel = 0;
          std::memcpy(&rel, ins + 2, 4);
          operand_value = static_cast<int64_t>(rel) + 6;
        } else {
          // Arctium 在这里 throw InvalidDataException；我们记录并跳过这一处，
          // 因为这只是"这个特征码命中的地方不像 remap 校验"，
          // 不该让整次安装失败。
          plan.notes.push_back("Remap 命中 0x" + to_hex(image_base + a, 16) +
                               " 之后的指令不是跳转，已跳过");
          continue;
        }

        const uint64_t jump_to_value =
            image_base + a + static_cast<uint64_t>(operand_value) + 4;

        // 全映像搜索：跳转目标正好是 jump_to_value 的跳转。
        //
        // 结构与 Arctium 完全一致：
        //     Parallel.For(lastAddress, Data.Length, i => {
        //         if (IsJump(i))           { ... E9 rel32+1 ... }
        //         else if (IsShortJump(i)) { ... EB（1 字节）... }
        //     });
        //
        // 两个判据（逐字节照抄 WinMemory.cs）：
        //     IsJump       : Data[i] == 0x0F && Data[i+1] in 0x80..0x8F
        //     IsShortJump  : Data[i]      in 0x70..0x7E      （Jcc rel8，【不含】0xEB）
        // 0xEB(235) 不落在 0x70..0x7E(112..126) 里，所以 EB 形态的 jmp rel8
        // 两条分支都不会匹配 —— 这是 Arctium 的原样行为，不要"顺手修"。
        // 短跳转分支额外要求 Data[i-3] == 0x48（它认定的 test 指令指示符）。
        for (size_t i = last_address; i + 6 <= n; ++i) {
          if (is_jump(d, n, i)) {
            int32_t jump_operand = 0;
            std::memcpy(&jump_operand, d + i + 2, 4);
            const int64_t jump_size =
                static_cast<int64_t>(jump_to_value) - static_cast<int64_t>(image_base + i) - 6;
            if (static_cast<int64_t>(jump_operand) == jump_size) {
              // 补丁点在跳转指令起点；rel32 +1 让落点错开 1 字节
              AntiCrashPatch p;
              p.va = image_base + i;
              const int32_t new_rel = static_cast<int32_t>(jump_size + 1);
              p.bytes = {0xE9, static_cast<uint8_t>(new_rel & 0xFF),
                         static_cast<uint8_t>((new_rel >> 8) & 0xFF),
                         static_cast<uint8_t>((new_rel >> 16) & 0xFF),
                         static_cast<uint8_t>((new_rel >> 24) & 0xFF)};
              p.name = "jmp_rel32@" + std::to_string(p.va);
              if (already.insert(p.va).second) {
                plan.patches.push_back(std::move(p));
                ++plan.remap_jump_patches;
              }
            }
          } else if (is_short_jump(d, n, i)) {
            const int jump_operand = d[i + 1];
            const int64_t jump_size =
                static_cast<int64_t>(jump_to_value) - static_cast<int64_t>(image_base + i) - 2;
            if (jump_operand == jump_size) {
              const bool has_48 = i >= 3 && d[i - 3] == 0x48;
              if (has_48) {
                AntiCrashPatch p;
                p.va = image_base + i;
                p.bytes = {0xEB};   // 1 字节，整体指令变短
                p.name = "jmp_rel8@" + std::to_string(p.va);
                if (already.insert(p.va).second) {
                  plan.patches.push_back(std::move(p));
                  ++plan.remap_jump_patches;
                }
              }
            }
          }
        }
        last_address = a;
      }
    }
  }

  // 一条都没找到不算失败：可能这个客户端版本本来就没有这些校验，
  // 也可能页面还没解密。如实报告，让调用方决定。
  plan.ok = true;
  if (plan.patches.empty())
    plan.notes.push_back("没有找到任何 integrity/remap 校验点（可能本版本没有，或该段尚未解密）");
  return plan;
}

const char* anticrash_integrity_pattern() { return kIntegrityPattern; }
const char* anticrash_integrity2_pattern() { return kIntegrity2Pattern; }
const char* anticrash_remap_pattern() { return kRemapPattern; }

const uint8_t* anticrash_integrity_bytes(size_t* len) {
  if (len) *len = sizeof(kIntegrityPatch);
  return kIntegrityPatch;
}

}  // namespace wowmod
