// Arctium mod 机制实现：改条件跳转，不装 hook。
// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "windows/arctium_patch.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "wowmod/arctium_sigs.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/util.hpp"
#include "windows/detour.hpp"
#include "windows/scan_images.hpp"

namespace wowmod {
namespace win {

namespace {

// 这两条是 Arctium 真正用来关掉 CASC 加载分支的特征码。
// 其余条目（CustomFileIdHook / FileIdLookupFNV / 旧版 LoadByFileId）不是补丁目标：
//   * CustomFileIdHook 是它【另一个】用途（替换返回值）的入口，我们暂不做；
//   * 旧版两条在 12.0.7 上命中 0 处。
bool is_patch_target(const std::string& name) {
  return name == "LoadByFileIdAlternate" || name == "LoadByFilePathAlternate";
}

std::string hex4(const uint8_t* b) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%02X %02X %02X %02X", b[0], b[1], b[2], b[3]);
  return buf;
}

}  // namespace

BranchPatchReport plan_branch_patches(HANDLE process) {
  BranchPatchReport rep;

  const auto images = scan_process_images(process);
  if (images.empty()) {
    rep.error = "没有扫到任何可执行映像（客户端可能还没解密完）";
    return rep;
  }

  size_t scanned = 0;
  for (const auto& s : arctium_signature_specs()) {
    if (!is_patch_target(s.name)) continue;

    BranchPatch p;
    p.name = s.name;
    p.pattern = s.pattern;
    p.patch_offset = s.patch_offset;

    std::string perr;
    const Pattern pat = Pattern::parse(s.pattern, &perr);
    if (!pat.valid()) {
      p.error = "特征码解析失败: " + perr;
      rep.patches.push_back(p);
      continue;
    }

    // 在【所有】映像里找。命中必须全局唯一：特征弱就会打到别的函数上，
    // 那是必然崩溃的下场，宁可不动。
    std::vector<std::pair<uint64_t, size_t>> hits;  // (VA, 映像内偏移)
    uint64_t image_base = 0;
    size_t image_size = 0;
    for (const auto& img : images) {
      if (img.bytes.empty()) continue;
      scanned += img.bytes.size();
      const auto offs = pat.find_all(img.bytes);
      for (size_t o : offs) {
        hits.push_back({img.base + o, o});
        image_base = img.base;
        image_size = img.size;
      }
    }

    if (hits.empty()) {
      p.error = "特征码一处理命中都没有 —— 这个版本的客户端里它不存在";
      rep.patches.push_back(p);
      continue;
    }
    if (hits.size() > 1) {
      p.error = "特征码命中 " + std::to_string(hits.size()) +
                " 处，不唯一，拒绝安装（打错位置必崩）";
      rep.patches.push_back(p);
      continue;
    }

    p.match_va = hits[0].first;
    p.patch_va = p.match_va + static_cast<uint64_t>(p.patch_offset);

    // 读回目标 4 字节，确认它真的是一条 je rel32。
    uint8_t cur[4] = {0, 0, 0, 0};
    std::string rerr;
    if (!read_remote(process, p.patch_va, cur, sizeof(cur), &rerr)) {
      p.error = "读取补丁点失败: " + rerr;
      rep.patches.push_back(p);
      continue;
    }
    if (!(cur[0] == 0x0F && cur[1] == 0x84)) {
      p.error = "补丁点不是 je rel32，实际字节 " + hex4(cur) + "（特征码与版本不匹配）";
      rep.patches.push_back(p);
      continue;
    }
    std::memcpy(p.original, cur, sizeof(cur));
    (void)image_base;
    (void)image_size;
    rep.patches.push_back(p);
  }

  size_t n = 0;
  for (const auto& p : rep.patches) {
    if (p.error.empty() && p.match_va != 0) ++n;
  }
  rep.applied_count = 0;
  rep.ok = (n > 0);
  if (n == 0) {
    rep.error = "没有任何一条可以安全安装的分支补丁";
  }
  (void)scanned;
  return rep;
}

bool apply_branch_patches(HANDLE process, BranchPatchReport* rep) {
  if (!rep) return false;

  std::vector<BranchPatch*> done;
  for (auto& p : rep->patches) {
    if (!p.error.empty() || p.match_va == 0) continue;

    // 写前重读：扫描与写入是两次独立读取。
    uint8_t cur[4] = {0, 0, 0, 0};
    std::string rerr;
    if (!read_remote(process, p.patch_va, cur, sizeof(cur), &rerr)) {
      p.error = "写前复读失败: " + rerr;
      continue;
    }
    if (std::memcmp(cur, p.original, sizeof(cur)) != 0) {
      p.error = "写前复读发现字节已变（壳重映射？）期望 " + hex4(p.original) +
                " 实际 " + hex4(cur);
      continue;
    }

    const uint8_t zero[4] = {0x00, 0x00, 0x00, 0x00};
    std::string werr;
    if (!write_remote(process, p.patch_va, zero, sizeof(zero), &werr)) {
      p.error = "写入失败: " + werr;
      continue;
    }

    // 回读确认真的写进去了。WriteProcessMemory 成功不代表内容如我们所愿
    // （页可能被壳重新加密）。回读不一致就当作失败并回滚这一条。
    uint8_t back[4] = {0, 0, 0, 0};
    if (!read_remote(process, p.patch_va, back, sizeof(back), &rerr) ||
        std::memcmp(back, zero, sizeof(back)) != 0) {
      p.error = "写入后回读不一致（实际 " + hex4(back) + "）";
      std::string ierr;
      write_remote(process, p.patch_va, p.original, sizeof(p.original), &ierr);
      continue;
    }

    p.applied = true;
    done.push_back(&p);
  }

  FlushInstructionCache(process, nullptr, 0);

  // 一条都没成功 → 整体失败。
  if (done.empty()) {
    rep->ok = false;
    if (rep->error.empty()) rep->error = "所有分支补丁都写入失败";
    return false;
  }

  rep->applied_count = done.size();
  rep->ok = true;
  return true;
}

bool revert_branch_patches(HANDLE process, BranchPatchReport* rep, std::string* err) {
  if (!rep) {
    if (err) *err = "空报告";
    return false;
  }
  bool all = true;
  for (auto& p : rep->patches) {
    if (!p.applied) continue;
    std::string werr;
    // 只在当前字节确实是我们的 00 00 00 00 时才写回；否则说明别人动过，不能覆盖。
    uint8_t cur[4] = {0, 0, 0, 0};
    std::string rerr;
    if (read_remote(process, p.patch_va, cur, sizeof(cur), &rerr)) {
      const bool ours = (cur[0] == 0 && cur[1] == 0 && cur[2] == 0 && cur[3] == 0);
      if (!ours) {
        if (err) *err += p.name + ": 当前字节不是我们的补丁，跳过 ";
        all = false;
        continue;
      }
    }
    if (write_remote(process, p.patch_va, p.original, sizeof(p.original), &werr)) {
      p.applied = false;
    } else {
      if (err) *err += p.name + ": 写回失败 " + werr + " ";
      all = false;
    }
  }
  FlushInstructionCache(process, nullptr, 0);
  return all;
}

std::string format_branch_patch_report(const BranchPatchReport& rep) {
  std::string t;
  t += "=========== Arctium 分支补丁（关闭 CASC 加载分支）===========\n";
  t += "机制来源: Arctium/WoW-Launcher  src/Launcher.cs + src/Patches/Windows.cs\n";
  t += "           补丁内容 = 4 个 0x00（NoJump），把 je rel32 改成「永不跳」\n\n";
  for (const auto& p : rep.patches) {
    t += "[" + p.name + "]\n";
    if (p.match_va != 0) {
      t += "  匹配  0x" + to_hex(p.match_va, 16) + "\n";
      t += "  补丁  0x" + to_hex(p.patch_va, 16) + "  (匹配+" +
           std::to_string(p.patch_offset) + ")\n";
      t += "  原字节 " + hex4(p.original) + " (je rel32)\n";
    }
    if (!p.error.empty()) t += "  [SKIPPED] 【跳过】" + p.error + "\n";
    else if (p.applied) t += "  [PATCHED] 【已打】je 已改为不跳\n";
    else t += "  [PLANNED] 【仅规划】尚未写入\n";
    t += "\n";
  }
  if (!rep.error.empty()) t += "整体: " + rep.error + "\n";
  else if (rep.ok) t += "整体: 可用（" + std::to_string(rep.applied_count) + " 条已写入）\n";
  return t;
}

}  // namespace win
}  // namespace wowmod
#endif
