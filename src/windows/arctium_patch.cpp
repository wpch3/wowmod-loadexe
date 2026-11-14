// Arctium mod 机制实现：改条件跳转，不装 hook。
// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "windows/arctium_patch.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

#include "wowmod/arctium_sigs.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/util.hpp"
#include "windows/detour.hpp"
#include "windows/scan_images.hpp"

namespace wowmod {
namespace win {

namespace {

bool is_patch_target(const std::string& name) {
  return name == "LoadByFileIdAlternate" || name == "LoadByFilePathAlternate";
}

std::string hex4(const uint8_t* b) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%02X %02X %02X %02X", b[0], b[1], b[2], b[3]);
  return buf;
}

std::string hexn(const uint8_t* b, size_t n, size_t max_n = 24) {
  std::string s;
  const size_t m = n < max_n ? n : max_n;
  char t[8];
  for (size_t i = 0; i < m; ++i) {
    std::snprintf(t, sizeof(t), "%02X ", b[i]);
    s += t;
  }
  if (n > m) s += "...";
  return s;
}

// 一处原始命中。
struct RawHit {
  uint64_t va = 0;
  uint64_t image_base = 0;
  size_t image_size = 0;
  size_t offset_in_image = 0;
  bool image_backed = false;     // MEM_IMAGE
  bool executable = false;
  std::string module;            // 属于哪个已加载模块（空 = 匿名区）
  std::string context;           // 命中处前 16 字节，用来判断是不是同一段代码
};


// 读取目标进程内存；整段失败就逐页读，缺页填 0（与 scan_images 同一策略）。
std::vector<uint8_t> read_exact(HANDLE process, uint64_t addr, size_t n) {
  std::vector<uint8_t> buf(n, 0);
  SIZE_T got = 0;
  if (ReadProcessMemory(process, reinterpret_cast<const void*>(addr), buf.data(), n, &got) &&
      got == n)
    return buf;
  for (size_t off = 0; off < n; off += 0x1000) {
    SIZE_T g = 0;
    const size_t m = std::min<size_t>(0x1000, n - off);
    ReadProcessMemory(process, reinterpret_cast<const void*>(addr + off), buf.data() + off, m, &g);
  }
  return buf;
}

// 就地修正：算出真正的补丁点、校验、并把每一处命中的元数据补全。
//
// 为什么需要这个函数 —— v13 实测暴露的两个错都出在这里：
//
//   1) 「采用」的那一处判成了不可执行。原因：枚举内存区时 VirtualQueryEx
//      常把「映像头部页（R）」和「.text 代码页（RX）」报成两个独立区域。
//      我们只在第一个区域里找特征串，找到的点自然落在 R 页上。可代码页
//      就在旁边，RVA 一模一样。所以「不可执行」不等于「不能改」——
//      只要同一 RVA 上存在可执行副本，就改那一份。
//   2) 补丁点读出来是 9C 00 00 00 / C0 00 00 00，报告写「原字节 00 00 00 00」。
//      这说明 match_va 本身就不对：特征串起点在 je 【之前 4 个字节】，
//      真正的 je 操作码在 match+1（01 是上一条 test 指令的立即数尾巴）。
//      所以补丁点必须在运行时【按操作码校验后重算】，不能硬信匹配起点。
static void verify_and_fix_hits(HANDLE process, const std::vector<ScannedImage>& images,
                                BranchPatch* p) {
  if (!p) return;

  // ---- 1) 选出要改的那一处 ----
  //
  // 只在【已经收集到的命中】里挑，绝不能拿 RVA 去别的映像里"推算"地址。
  // v14 的 bug 就是这么来的：看到命中报「不可执行」，就遍历所有可执行映像、
  // 把 RVA 直接加上去，于是算出 0x7FFCD0046976 这种毫不相干的地址，
  // 在那里读到 86 DD 12 00，校验必然失败。
  //
  // 正确判据：同一 RVA 上若存在可执行的那一份，就用它；否则用原来的。
  uint64_t best_va = p->match_va;
  bool best_exec = false;
  {
    bool found_exec = false;
    for (const auto& h : p->hits) {
      if (h.rva_in_image != p->rva_in_image) continue;
      if (h.executable) {
        best_va = h.va;
        best_exec = true;
        found_exec = true;
        break;
      }
    }
    if (!found_exec) {
      for (const auto& h : p->hits) {
        if (h.va == p->match_va) { best_exec = h.executable; break; }
      }
    }
  }

  // ---- 2) 读窗口，按操作码定位 je ----
  //
  // 期望形态：<前缀> 0F 84 <rel32>。12.0.7 的实测形态是
  //   01 0F 84 9C 00 00 00
  //   ^^ ^^^^^^^^^^^^^^^^ 上一条 test bpl,1 的立即数尾巴 + je rel32
  // 所以 je 操作码在匹配起点 +1，rel32 在 +3（= patch_offset）。
  //
  // 优先采用「与签名导出时一致的偏移」；不一致才退化为就近搜索，
  // 但会把实际用到的偏移写进报告，绝不让报告和自己矛盾。
  const auto win = read_exact(process, best_va, 16);
  char win_hex[64];
  std::snprintf(win_hex, sizeof(win_hex), "%02X %02X %02X %02X %02X %02X %02X %02X",
                win[0], win[1], win[2], win[3], win[4], win[5], win[6], win[7]);
  p->window_bytes = win_hex;

  const int expected_je_at = p->patch_offset - 2;  // 3 - 2 = 1
  int je_at = -1;
  if (expected_je_at >= 0 && expected_je_at + 6 <= static_cast<int>(win.size()) &&
      win[expected_je_at] == 0x0F && win[expected_je_at + 1] == 0x84) {
    je_at = expected_je_at;
  } else {
    // 签名偏移对不上：就近搜一次，但只在前 6 字节里找，避免抓到下一条指令
    for (int i = 0; i + 6 <= static_cast<int>(win.size()) && i <= 5; ++i) {
      if (win[i] == 0x0F && win[i + 1] == 0x84) { je_at = i; break; }
    }
  }
  if (je_at < 0) {
    p->error = std::string("在 0x") + to_hex(best_va, 0) +
               " 处读到的字节是 " + win_hex + "，前 6 字节里没有 0F 84（je rel32）";
    return;
  }

  p->je_opcode_offset = je_at;
  p->match_va = best_va;
  p->executable_copy = best_exec;
  p->patch_va = p->match_va + static_cast<uint64_t>(je_at) + 2;  // rel32 起点

  // ---- 3) 拆出补丁点 4 字节 = je 的 rel32 ----
  uint8_t rel32[4];
  std::memcpy(rel32, win.data() + je_at + 2, 4);
  std::memcpy(p->original, rel32, 4);

  // je 目标 = 下一条指令地址（patch_va + 4）+ rel32
  const int32_t rel = static_cast<int32_t>(static_cast<uint32_t>(rel32[0]) |
                                           (static_cast<uint32_t>(rel32[1]) << 8) |
                                           (static_cast<uint32_t>(rel32[2]) << 16) |
                                           (static_cast<uint32_t>(rel32[3]) << 24));
  p->jump_target = p->patch_va + 4 + static_cast<int64_t>(rel);

  // ---- 4) 合理性校验：rel32 必须指向同一映像内、且方向朝后（前向跳转） ----
  const bool forward = rel > 0;
  if (!forward || rel > 0x100000) {
    p->error = "je 的 rel32 不合理（rel=" + std::to_string(rel) +
               "），这不是我们想要的那条前向条件跳转";
    return;
  }

  p->error.clear();
}

}  // namespace

BranchPatchReport plan_branch_patches(HANDLE process,
                                      const std::map<std::string, uint32_t>& rva_override) {
  BranchPatchReport rep;

  const auto images = scan_process_images(process);
  if (images.empty()) {
    rep.error = "没有扫到任何可执行映像（客户端可能还没解密完）";
    return rep;
  }

  // 主模块基址：报告里给出，方便把 RVA 换算成绝对地址核对。
  {
    uint64_t mb = 0;
    size_t ms = 0;
    if (module_range(process, L"", &mb, &ms)) rep.main_module_base = mb;
  }

  for (const auto& s : arctium_signature_specs()) {
    if (!is_patch_target(s.name)) continue;

    BranchPatch p;
    p.name = s.name;
    p.patch_offset = s.patch_offset;

    // ---- 第一步：优先用无通配的长精确签名 ----
    //
    // 这是本次修正的核心。Arctium 的原始特征码 17 字节里 13 个通配位，
    // 只约束 4 个字节；它只扫主模块所以够用，我们扫全进程 200+ MB 就会命中十几处。
    // 用户实测：LoadByFileIdAlternate 命中 10 处、LoadByFilePathAlternate 命中 2 处。
    //
    // 强签名由 12.0.7 解密映像逐字节反汇编导出，无通配，离线两份 dump 各 1 处。
    std::vector<RawHit> hits;
    std::string used_pattern;
    bool used_strong = false;

    if (s.strong_pattern && s.strong_pattern[0] != '\0') {
      std::string perr;
      const Pattern strong = Pattern::parse(s.strong_pattern, &perr);
      if (strong.valid()) {
        for (const auto& img : images) {
          if (img.bytes.empty()) continue;
          const auto offs = strong.find_all(img.bytes);
          for (size_t o : offs) {
            RawHit h;
            h.va = img.base + o;
            h.image_base = img.base;
            h.image_size = img.size;
            h.offset_in_image = o;
            h.image_backed = img.region_type == MEM_IMAGE;
            h.executable = img.executable;
            h.module = img.module_name;
            if (o >= 16)
              h.context = hexn(img.bytes.data() + o - 16, 16);
            hits.push_back(h);
          }
        }
        used_pattern = s.strong_pattern;
        used_strong = !hits.empty();
      }
    }

    // 强签名在运行时找不到（比如客户端换版本）→ 退回 Arctium 原始特征码，
    // 但【绝不因为多处命中就瞎选】，而是把全部命中报出来。
    if (hits.empty()) {
      std::string perr;
      const Pattern pat = Pattern::parse(s.pattern, &perr);
      if (!pat.valid()) {
        p.error = "特征码解析失败: " + perr;
        rep.patches.push_back(p);
        continue;
      }
      for (const auto& img : images) {
        if (img.bytes.empty()) continue;
        const auto offs = pat.find_all(img.bytes);
        for (size_t o : offs) {
          RawHit h;
          h.va = img.base + o;
          h.image_base = img.base;
          h.image_size = img.size;
          h.offset_in_image = o;
          h.image_backed = img.region_type == MEM_IMAGE;
          h.executable = img.executable;
          h.module = img.module_name;
          if (o >= 16) h.context = hexn(img.bytes.data() + o - 16, 16);
          hits.push_back(h);
        }
      }
      used_pattern = s.pattern;
    }

    p.pattern = used_pattern;

    // ---- 记录每一处命中，作为证据写进报告 ----
    // 用户需要看到「到底命中在哪」，否则无法判断下一步怎么做。
    for (const auto& h : hits) {
      PatchHitInfo info;
      info.va = h.va;
      info.rva_in_image = h.offset_in_image;
      info.image_base = h.image_base;
      info.image_size = h.image_size;
      info.module = h.module;
      info.image_backed = h.image_backed;
      info.executable = h.executable;
      info.context = h.context;
      p.hits.push_back(info);
    }

    if (hits.empty()) {
      p.error = "特征码一处理命中都没有 —— 这个版本的客户端里它不存在";
      rep.patches.push_back(p);
      continue;
    }

    // ---- 第二步：用户点名优先 ----
    //
    // 如果调用方用 --rva 点名了这条，就按 RVA 找那一处，跳过自动判定。
    // 这是给「同一段代码被映射多份」这种局面准备的人工兜底 —— 自动判定宁可
    // 拒绝也不猜，但用户手上有离线 dump 的实测 RVA 时可以直接指定。
    {
      const auto it = rva_override.find(std::string(s.name));
      if (it != rva_override.end()) {
        p.overridden = true;
        const RawHit* chosen = nullptr;
        for (const auto& h : hits) {
          if (h.offset_in_image == it->second) { chosen = &h; break; }
        }
        if (!chosen) {
          p.error = "用户点名的 RVA 0x" + to_hex(it->second, 0) +
                    " 在本次扫描里没有命中（特征码不同或代码未解密）";
          rep.patches.push_back(p);
          continue;
        }
        if (!chosen->executable) {
          p.error = "用户点名的 RVA 0x" + to_hex(it->second, 0) + " 不在可执行页上，拒绝";
          rep.patches.push_back(p);
          continue;
        }
        p.match_va = chosen->va;
        p.patch_va = p.match_va + static_cast<uint64_t>(p.patch_offset);
        p.rva_in_image = chosen->offset_in_image;
        p.image_base = chosen->image_base;
        p.used_strong = used_strong;
        verify_and_fix_hits(process, images, &p);
        rep.patches.push_back(p);
        continue;
      }
    }

    // ---- 第二步：去重与筛选 ----
    //
    // 同一段代码可能被映射多份（壳常见做法）。判据：
    //   1. 优先只保留 MEM_IMAGE（模块本体）—— 那是唯一应该改写的副本，
    //      MEM_MAPPED 可能是共享视图，改它会污染别的进程。
    //   2. 都排除后仍有多处 → 用「命中处前 16 字节上下文」分组：
    //      上下文完全一致说明是同一份代码的多个副本，可用；不一致说明是
    //      不同函数撞了同一串字节，必须拒绝。
    std::vector<size_t> candidates;
    for (size_t i = 0; i < hits.size(); ++i) {
      if (hits[i].executable) candidates.push_back(i);
    }
    if (candidates.empty()) {
      p.error = "命中处都不在可执行页上，拒绝安装";
      rep.patches.push_back(p);
      continue;
    }

    std::vector<size_t> image_backed;
    for (size_t i : candidates) {
      if (hits[i].image_backed) image_backed.push_back(i);
    }
    const std::vector<size_t>& pool = image_backed.empty() ? candidates : image_backed;

    // ---- 最强判别：离线确证的 RVA ----
    //
    // 如果这条特征码带了 known_rva（在已确证的 12.0.7 build 68974 上实测的 RVA），
    // 而某些命中的 RVA 正好等于它，那些命中就是我们要的那个函数本体，
    // 其余全是同一段代码的其他副本或巧合。这是比「上下文一致」更硬的证据：
    // RVA 是绝对位置，副本的 RVA 不会刚好相同。
    if (s.known_rva != 0) {
      std::vector<size_t> by_rva;
      for (size_t i : pool) {
        if (hits[i].offset_in_image == s.known_rva) by_rva.push_back(i);
      }
      if (by_rva.size() == 1) {
        const RawHit& h = hits[by_rva[0]];
        p.match_va = h.va;
        p.patch_va = p.match_va + static_cast<uint64_t>(p.patch_offset);
        p.rva_in_image = h.offset_in_image;
        p.image_base = h.image_base;
        p.used_strong = used_strong;
        p.matched_known_rva = true;
        verify_and_fix_hits(process, images, &p);
        rep.patches.push_back(p);
        continue;
      }
    }

    if (pool.size() == 1) {
      // 最好情况：唯一命中。
    } else {
      // 多处：看上下文是否一致。
      std::set<std::string> ctx;
      for (size_t i : pool) ctx.insert(hits[i].context);
      if (ctx.size() > 1) {
        p.error = "命中 " + std::to_string(hits.size()) + " 处（其中 " +
                  std::to_string(pool.size()) + " 处在可执行映像内），且上下文不一致 " +
                  std::to_string(ctx.size()) +
                  " 种 —— 是不同的函数撞了同一串字节，拒绝安装";
        rep.patches.push_back(p);
        continue;
      }
      p.error = "命中 " + std::to_string(hits.size()) + " 处（其中 " +
                std::to_string(pool.size()) + " 处在可执行映像内），上下文一致 = 同一段代码被映射多份。" +
                "为避免改错副本，拒绝安装（需要 --rva 指定目标）";
      rep.patches.push_back(p);
      continue;
    }

    const RawHit& h = hits[pool[0]];
    p.match_va = h.va;
    p.patch_va = p.match_va + static_cast<uint64_t>(p.patch_offset);
    p.rva_in_image = h.offset_in_image;
    p.image_base = h.image_base;
    p.used_strong = used_strong;

    verify_and_fix_hits(process, images, &p);
    rep.patches.push_back(p);
  }

  size_t n = 0;
  for (const auto& p : rep.patches) {
    if (p.error.empty() && p.match_va != 0) ++n;
  }
  rep.ok = (n > 0);
  if (n == 0) rep.error = "没有任何一条可以安全安装的分支补丁";
  rep.plannable = n;
  return rep;
}

bool apply_branch_patches(HANDLE process, BranchPatchReport* rep) {
  if (!rep) return false;

  std::vector<BranchPatch*> done;
  for (auto& p : rep->patches) {
    if (!p.error.empty() || p.match_va == 0) continue;

    // 写前重读：扫描与写入是两次独立读取，中间壳可能重映射过。
    uint8_t cur[4] = {0, 0, 0, 0};
    std::string rerr;
    if (!read_remote(process, p.patch_va, cur, sizeof(cur), &rerr)) {
      p.error = "写前复读失败: " + rerr;
      continue;
    }
    if (std::memcmp(cur, p.original, sizeof(cur)) != 0) {
      p.error = "写前复读发现字节已变（壳重映射？）期望 " + hex4(p.original) + " 实际 " +
                hex4(cur);
      continue;
    }

    const uint8_t zero[4] = {0x00, 0x00, 0x00, 0x00};
    std::string werr;
    if (!write_remote(process, p.patch_va, zero, sizeof(zero), &werr)) {
      p.error = "写入失败: " + werr;
      continue;
    }

    // 回读确认：WriteProcessMemory 成功不代表内容如我们所愿。
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
    std::string werr;
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
  t += "           补丁内容 = 4 个 0x00（NoJump），把 je rel32 改成「永不跳」\n";
  if (rep.main_module_base != 0) {
    char l[160];
    std::snprintf(l, sizeof(l), "主模块基址: 0x%llX\n",
                  static_cast<unsigned long long>(rep.main_module_base));
    t += l;
  }
  t += "\n";

  for (const auto& p : rep.patches) {
    t += "[" + p.name + "]\n";
    if (!p.hits.empty()) {
      t += "  命中 " + std::to_string(p.hits.size()) + " 处:\n";
      for (size_t i = 0; i < p.hits.size(); ++i) {
        const auto& h = p.hits[i];
        char line[320];
        std::snprintf(line, sizeof(line),
                      "    #%-2zu VA 0x%llX  rva 0x%zx  %s  %s%s\n       上下文 %s\n",
                      i + 1, static_cast<unsigned long long>(h.va), h.rva_in_image,
                      h.module.empty() ? "(匿名区)" : h.module.c_str(),
                      h.image_backed ? "MEM_IMAGE" : "非映像",
                      h.executable ? " 可执行" : " 不可执行", h.context.c_str());
        t += line;
        if (h.executable_copy_va && h.executable_copy_va != h.va) {
          std::snprintf(line, sizeof(line), "       可执行副本 0x%llX  %s\n",
                        static_cast<unsigned long long>(h.executable_copy_va),
                        h.executable_copy_module.empty() ? "(匿名区)"
                                                        : h.executable_copy_module.c_str());
          t += line;
        }
      }
    }
    if (p.match_va != 0) {
      char line[320];
      std::snprintf(line, sizeof(line), "  采用  0x%llX  (rva 0x%zx)  签名=%s%s\n",
                    static_cast<unsigned long long>(p.match_va), p.rva_in_image,
                    p.used_strong ? "精确长签名" : "Arctium 原始特征码",
                    p.overridden ? "  [用户 --rva 点名]"
                                 : (p.matched_known_rva ? "  [命中确证 RVA]" : ""));
      t += line;
      std::snprintf(line, sizeof(line),
                    "  窗口 %s\n", p.window_bytes.c_str());
      t += line;
      std::snprintf(line, sizeof(line),
                    "  采用点 %s\n", p.executable_copy ? "可执行" : "不可执行");
      t += line;
      std::snprintf(line, sizeof(line),
                    "  补丁点 0x%llX  (匹配+%d，即 je 操作码 +2 指向 rel32)\n",
                    static_cast<unsigned long long>(p.patch_va),
                    p.je_opcode_offset + 2);
      t += line;
      std::snprintf(line, sizeof(line), "  原字节 %s (je rel32)\n", hex4(p.original).c_str());
      t += line;
      if (p.jump_target != 0) {
        std::snprintf(line, sizeof(line), "  je 目标 0x%llX\n",
                      static_cast<unsigned long long>(p.jump_target));
        t += line;
      }
    }
    if (!p.error.empty()) t += "  [SKIPPED] 【跳过】" + p.error + "\n";
    else if (p.applied) t += "  [PATCHED] 【已打】je 已改为不跳\n";
    else t += "  [PLANNED] 【仅规划】尚未写入\n";
    t += "\n";
  }

  if (!rep.error.empty()) t += "整体: " + rep.error + "\n";
  else if (rep.ok)
    t += "整体: 可用（" + std::to_string(rep.applied_count) + " 条已写入）\n";
  return t;
}

}  // namespace win
}  // namespace wowmod
#endif
