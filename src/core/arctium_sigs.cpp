// Arctium 特征码表（纯数据）。
// SPDX-License-Identifier: MIT
#include "wowmod/arctium_sigs.hpp"

#include <cstring>

namespace wowmod {

namespace {
const std::vector<ArctiumSignatureSpec> kSpecs = {
    // 文件打开函数本体 —— 真正的 mod hook 点。rdx = FileDataID，返回 rax = 路径指针。
    // Arctium 在这条特征的起点装 15 字节绝对 jmp，跳到它自己的查表 stub。
    {"CustomFileIdHook",
     "48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? "
     "48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD",
     0, "Arctium 直接在这些字节处装 15 字节 jmp，换成查表 stub"},

    // 第二张 FileDataID 哈希表（12.0.7 唯一命中 RVA 0x33e05c0）。
    //
    // 与上面的 CustomFileIdHook 是【两张不同的表】：
    //   CustomFileIdHook : murmur(0xff51afd7ed558ccd) + 桶指针 + 节点 16 字节
    //   本特征码        : FNV-1a(0xcbf29ce484222325 / 0x100000001b3) + 元素 44 字节
    //
    // 它【不是】模组加载点，而是 LoadByFileId 内部的第一步查找（见下）。实测调用序
    // 0x33d7959 call 0x33e05c0  →  0x33d7986 call 0x33e06a0，两者都在同一个文件打开
    // 函数里、共用 rdx=FileDataID。早期探针挂在这里却只记录到 interface//sound/，
    // 是因为它 0x33d7973 处 test bpl,1 的 bpl 由该函数第 4 个参数 r8d 传入，
    // 探针触发的那条路径本身就只走界面/音效，不能据此判断它「管什么资源」。
    {"FileIdLookupFNV",
     "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 8B 11 48 B8 25 23 22 84 E4 9C F2 CB "
     "44 8B DA",
     0, "FNV-1a 哈希的 FileDataID 查找（元素步长 0x2C）"},

    // ------------------------------------------------------------------
    // Arctium 用来判断「客户端初始化完成、代码可以扫了」的特征码。
    //
    // 这是它 WaitForUnpack() 的判据，源码原文：
    //     var initOffset = memory.Read(...)?.FindPattern(Patterns.Windows.Init) ?? 0;
    //     while (initOffset == 0) { ... 重读 ... }
    //     while (memory.Read(initOffset + base, 1)?[0] == 0)
    //         memory.Data = memory.Read(mbi.BaseAddress, (int)mbi.RegionSize);
    //
    // 关键点：它等的【不是】「明文页比例够高」，而是「这条特征码出现了」。
    // 前者是我们自己发明、且在你机器上永远达不到的间接指标（惰性解密下
    // 明文比例稳定在 ~139 页就不再涨）；后者是直接指标，客户端初始化完
    // 就成立，不需要用户先进到登录界面。
    //
    // 原始（Arctium）: C7 05 ?? ?? ?? ?? 01 00 00 00 48 8D ?? ?? ?? ?? ?? 48 8D
    //                  ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 85            25 字节，6 个通配段
    {"Init",
     "C7 05 ?? ?? ?? ?? 01 00 00 00 48 8D ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? E8 "
     "?? ?? ?? ?? 85",
     0, "客户端初始化完成的标志（Arctium WaitForUnpack 的判据）"},

    // ------------------------------------------------------------------
    // Arctium 的【真正 mod 机制】：不是替换 CustomFileIdHook 的返回值，
    // 而是把这两处「按 FileDataID / 按路径从 CASC 加载」的条件跳转【改成不跳】。
    //
    //   je 0x33d7a19  <- 打掉它 → 跳过 CASC 分支，rdi 保持为 0
    //   je 0x33d7c1f  <- 打掉它 → 跳过 CASC 分支
    //   ... 于是函数返回 false，上层把这次读取当成「CASC 里没有」，
    //   转而在 mappings/*.txt + files/ 里查 FileDataID 对应的本地文件。
    //
    // 补丁内容就是 4 个 0x00（Arctium Patches.Windows.NoJump）。
    // patch_offset 是【相对匹配起点的偏移】，这两个值来自 12.0.7 实测反汇编：
    //   0x33d7977  test bpl,1
    //   0x33d797a  je 0x33d7a19      <- 匹配起点 0x33d7976，偏移 3 指向 je 的 4 字节位移
    //   0x33d7b55  test sil,1
    //   0x33d7b58  je 0x33d7c1f      <- 匹配起点 0x33d7b58，偏移 3 同上
    //
    // 注意：这两个偏移（3）与旧 10.x 分支用的 6 不同，因为匹配起点不同。
    //
    // strong_pattern 说明：这两条长签名由 12.0.7 (build 68974) 解密映像的实测反汇编
    // 逐字节导出，【完全没有通配位】。在 113,565,696 字节的主模块映像里精确命中 1 处
    // （另外用 main-module2.rar 的另一份 dump 交叉验证，同样 1 处）。
    // 长度 53 / 39 字节，不会和别的函数撞车。
    {"LoadByFileIdAlternate",
     "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 8B ?? E8", 3,
     "12.0.7 唯一命中 0x33d7976。je 改成不跳 = 关掉 CASC 加载分支，模组文件的入口",
     "01 0F 84 9C 00 00 00 48 8B 0D 4C 01 FD 00 8B D6 E8 15 8D 00 00 48 85 C0 "
     "74 05 49 8B FC EB 20 48 85 FF 0F 84 CF 00 00 00 48 8B 17 45 33 C0 48 8B 0D 25 01 FD 00",
     0x33d7976, 68974},
    {"LoadByFilePathAlternate",
     "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 44 89 ?? ?? ?? 00 00 00 48 85 C9", 3,
     "12.0.7 唯一命中 0x33d7b58。同上，路径型资源（如 textures 相对路径）用这条",
     "01 0F 84 C0 00 00 00 48 8B 0D 6A FF FC 00 44 89 A4 24 C0 00 00 00 "
     "48 85 C9 0F 84 A8 00 00 00 4C 8D 84 24 C0 00 00 00",
     0x33d7b58, 68974},

    // 旧版（10.x 之前）的特征串，保留以便识别老客户端。12.0.7 上命中 0 处。
    {"LoadByFileId",
     "41 ?? ?? 01 0F 84 ?? 00 00 00 48 8B ?? ?? ?? ?? ?? 8B", 6,
     "10.x 之前的分支特征；patch_offset=6 指向 je 的 4 字节相对位移。12.0.7 上不命中"},
    {"LoadByFilePath",
     "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 44 89 ?? ?? ?? 48 85 C9", 3,
     "10.x 之前的路径型分支。12.0.7 上不命中"},
};
}  // namespace

const std::vector<ArctiumSignatureSpec>& arctium_signature_specs() { return kSpecs; }


namespace {
bool window_has_je(const std::vector<uint8_t>& b) {
  for (size_t i = 0; i + 1 < b.size() && i <= 5; ++i)
    if (b[i] == 0x0F && b[i + 1] == 0x84) return true;
  return false;
}
}  // namespace

uint64_t pick_hook_target(const std::vector<HitCandidate>& cands, int* score_out) {
  uint64_t best_va = 0;
  int best_score = 0;
  for (const auto& c : cands) {
    // executable 不参与筛选 —— 这是 Arctium 的行为，也是修掉
    // "CustomFileIdHook 1 处 (可执行 否)" 导致跳板没装的关键。
    if (best_va == 0 || c.semantic_score > best_score) {
      best_va = c.va;
      best_score = c.semantic_score;
    }
  }
  if (score_out) *score_out = best_score;
  return best_va;
}

uint64_t compute_init_flag_address(uint64_t init_va, int32_t rel32) {
  if (!init_va) return 0;
  // 指令是 `C7 05 <rel32> <imm32>`，共 10 字节；rel32 相对下一条指令。
  return init_va + 10 + static_cast<int64_t>(rel32);
}

bool unpack_is_done(bool init_seen, bool flag_read_ok, uint8_t flag_value) {
  return init_seen && flag_read_ok && flag_value != 0;
}

bool resolve_site_window(std::vector<uint8_t> live,
                         const std::vector<uint8_t>* scanned,
                         uint64_t rva_in_image) {
  if (!scanned || live.size() < 16) return window_has_je(live);
  if (window_has_je(live)) return true;
  if (rva_in_image + 16 > scanned->size()) return false;
  std::vector<uint8_t> alt(16);
  std::memcpy(alt.data(), scanned->data() + rva_in_image, 16);
  return window_has_je(alt);
}

}  // namespace wowmod
