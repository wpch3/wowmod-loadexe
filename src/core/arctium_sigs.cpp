// Arctium 特征码表（纯数据）。
// SPDX-License-Identifier: MIT
#include "wowmod/arctium_sigs.hpp"

namespace wowmod {

namespace {
const std::vector<ArctiumSignatureSpec> kSpecs = {
    // 文件打开函数本体 —— 真正的 mod hook 点。rdx = FileDataID，返回 rax = 路径指针。
    // Arctium 在这条特征的起点装 15 字节绝对 jmp，跳到它自己的查表 stub。
    {"CustomFileIdHook",
     "48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? "
     "48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD",
     0, "Arctium 直接在这些字节处装 15 字节 jmp，换成查表 stub"},

    // 第二张 FileDataID 哈希表（12.0.7 新增发现，实测唯一命中 RVA 0x33e05c0）。
    //
    // 与上面的 CustomFileIdHook 是【两张不同的表】：
    //   CustomFileIdHook : murmur(0xff51afd7ed558ccd) + 桶指针 + 节点 16 字节
    //   本特征码        : FNV-1a(0xcbf29ce484222325 / 0x100000001b3) + 元素 44 字节
    // 判据来自反汇编：mov r10,[rcx] / movabs rax,0xcbf29ce484222325 /
    // mov r11d,edx / 逐字节混合 dl、>>8、>>16、>>24 / imul rax,r8,0x2c
    //
    // 为什么要加它：CustomFileIdHook 那个函数经探针实测只加载 interface/ 与 sound/，
    // character/ 一次都没有。角色模型贴图必然走别的查找路径，这一张是最有可能的。
    {"FileIdLookupFNV",
     "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 8B 11 48 B8 25 23 22 84 E4 9C F2 CB "
     "44 8B DA",
     0, "FNV-1a 哈希的 FileDataID 查找（元素步长 0x2C）"},

    // 「按 FileDataID 从 CASC 加载」分支。
    {"LoadByFileId",
     "41 ?? ?? 01 0F 84 ?? 00 00 00 48 8B ?? ?? ?? ?? ?? 8B", 6,
     "10.x 之前的分支特征；patch_offset=6 指向 je 的 4 字节相对位移"},
    {"LoadByFileIdAlternate", "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 8B ?? E8", 3,
     "Arctium 对 10.0+ 使用这条"},

    // 「按路径从 CASC 加载」分支。
    {"LoadByFilePath",
     "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 44 89 ?? ?? ?? 48 85 C9", 3,
     "路径型覆盖的分支"},
    {"LoadByFilePathAlternate",
     "01 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 44 89 ?? ?? ?? 00 00 00 48 85 C9", 3,
     "10.0+ 变体"},
};
}  // namespace

const std::vector<ArctiumSignatureSpec>& arctium_signature_specs() { return kSpecs; }

}  // namespace wowmod
