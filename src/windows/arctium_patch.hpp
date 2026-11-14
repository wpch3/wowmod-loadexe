// Arctium 的 mod 机制本体：把「按 FileDataID / 按路径从 CASC 加载」的条件跳转
// 改成【不跳】，让客户端以为 CASC 里没有这个资源，从而回头查本地文件。
//
// 这不是我们的发明，而是 Arctium/WoW-Launcher（MIT）的实际做法：
//   src/Launcher.cs        -> QueuePatch(Patterns.Windows.LoadByFileIdAlternate,
//                                          Patches.Windows.NoJump, "LoadByFileId", 3)
//                            QueuePatch(Patterns.Windows.LoadByFilePathAlternate,
//                                       Patches.Windows.NoJump, "LoadByFilePath", 3)
//   src/Patches/Windows.cs -> NoJump = { 0x00, 0x00, 0x00, 0x00 }
//
// 关键点：它【不 hook 任何函数入口】，只改 4 个字节的 rel32 条件跳转，
// 所以不需要搬运指令、不需要跳板、不会有撕裂写入、不会被壳的完整性校验打到。
//
// 12.0.7 实测（113,565,696 字节主模块解密映像）：
//   LoadByFileIdAlternate   唯一命中 0x33d7976，补丁点 0x33d797a（je → 4 个 0x00）
//   LoadByFilePathAlternate 唯一命中 0x33d7b58，补丁点 0x33d7b5b（je → 4 个 0x00）
// 两条都是 1 处命中，因此可以安全地按「必须唯一」来安装。
//
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

// 一处原始命中（写进报告，供人核对「到底命中在哪」）。
// 用户实测过「命中 10 处」这种局面，不给证据就无法继续判断。
struct PatchHitInfo {
  uint64_t va = 0;               // 绝对虚拟地址
  size_t rva_in_image = 0;       // 相对所在映像的 RVA
  uint64_t image_base = 0;
  size_t image_size = 0;
  std::string module;            // 所属模块名（空 = 匿名分配区）
  bool image_backed = false;     // MEM_IMAGE（模块本体）才是该改写的副本
  bool executable = false;
  std::string context;           // 命中处前 16 字节，用于判断是否同一段代码
  // 有些副本落在「只读、不标可执行」的区域（映像头部页），
  // 但同一 RVA 在代码页上有可执行映射。这里记下那个地址，改写要走它。
  uint64_t executable_copy_va = 0;
  std::string executable_copy_module;
};

// 一个待打的条件跳转。
struct BranchPatch {
  std::string name;              // 特征码名（LoadByFileIdAlternate / ...）
  std::string pattern;           // 实际用到的特征串（强签名或原始）
  int patch_offset = 0;          // 匹配起点 → 4 字节 rel32 的偏移
  uint64_t match_va = 0;         // 匹配到的虚拟地址
  uint64_t patch_va = 0;         // match_va + patch_offset
  size_t rva_in_image = 0;       // 采用点的 RVA
  uint64_t image_base = 0;
  uint64_t jump_target = 0;      // 原 je 跳到哪里（0 = 未知）
  bool used_strong = false;      // 是否用的无通配长签名
  bool overridden = false;       // 是否由 --rva 点名
  bool matched_known_rva = false;  // 是否由离线确证的 RVA 命中
  int je_opcode_offset = 0;        // je 操作码相对匹配起点的偏移（实测 = 1）
  bool executable_copy = false;    // 是否找到了可执行副本并按它改
  uint8_t original[4] = {0, 0, 0, 0};  // 原始 rel32（卸载时写回）
  std::vector<PatchHitInfo> hits;      // 全部原始命中
  bool applied = false;
  std::string error;             // 失败原因（人话，不是错误码）
};

struct BranchPatchReport {
  std::vector<BranchPatch> patches;
  std::string error;             // 整体失败原因
  bool ok = false;
  size_t applied_count = 0;
  size_t plannable = 0;          // 通过全部校验、可以安全写入的条数
  uint64_t main_module_base = 0; // 主模块基址（报告里给出，方便换算绝对地址）
};

// 只搜索、不写入。用于「演练」和给用户看命中位置。
// 命中数 != 1 的目标会被标记 error 并跳过 —— 特征太弱的绝不能打。
//
// rva_override: 名称 → RVA。当自动判定因「同一段代码被映射多份」而拒绝时，
// 用它可以点名要改哪一份（RVA 相对主模块）。空 map = 纯自动判定。
BranchPatchReport plan_branch_patches(
    HANDLE process,
    const std::map<std::string, uint32_t>& rva_override = {});

// 真正写入：把 patch_va 处的 4 字节改成 00 00 00 00。
// 写入前会重新读一遍，确认那 4 字节此刻仍是 0F 84（je rel32）：
// 扫描和写入是两次独立读取，中间壳可能重映射过这块内存。
// 任何一步失败都会把已经改过的那些写回原值，不留半装状态。
bool apply_branch_patches(HANDLE process, BranchPatchReport* rep);

// 卸载：把 original 写回。查不到原值就拒绝（不能瞎写）。
bool revert_branch_patches(HANDLE process, BranchPatchReport* rep, std::string* err);

// 人类可读报告（也用于写进日志文件）。
std::string format_branch_patch_report(const BranchPatchReport& rep);

}  // namespace win
}  // namespace wowmod
#endif
