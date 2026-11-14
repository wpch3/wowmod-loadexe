// Arctium 公开特征码表（可移植，不依赖 windows.h）。
//
// 来源：Arctium/WoW-Launcher（MIT）
//   src/Patterns/Windows.cs  -> CustomFileIdHook / LoadByFileId / LoadByFilePath
//   src/Patches/Windows.cs   -> NoJump = { 0x00, 0x00, 0x00, 0x00 }
//
// 这里只放数据，不放平台代码，这样主机上的单元测试也能校验表本身
// （能否解析、改写偏移是否合理），而真正的客户端匹配结果只在 Windows 上现场产生。
//
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <vector>

namespace wowmod {

// Arctium 的改写方式：把 patch_offset 处的 4 字节跳转条件改成 0，
// 让函数不再进入「从 CASC 加载」的分支。
struct ArctiumSignatureSpec {
  const char* name;
  const char* pattern;   // IDA 风格，?? = 通配
  int patch_offset;      // 从匹配起点到要改写的分支偏移
  const char* note;

  // ---- 可选：强校验信息 ----
  //
  // 为什么需要：Arctium 的原始特征码通配位极多（17 字节里 13 个 ??），
  // 只约束了 4 个字节。它只扫「主模块」且默认唯一，所以够用；
  // 而我们为了覆盖壳把代码解密到别的分配的情况，要扫全进程 200+ MB，
  // 同一段代码的多个副本 + 其他函数的巧合序言会让它命中十几处。
  //
  // 所以补两条硬约束：
  //   strong_pattern : 由实测反汇编导出、【无通配】的长签名，全映像唯一
  //   known_rva      : 在已确证的客户端版本上的 RVA，只在该版本上作为附加校验
  // 两者都为空时，行为退回「纯 Arctium 特征码」，即旧逻辑。
  const char* strong_pattern = nullptr;  // 可空
  uint32_t known_rva = 0;                // 0 = 不知道
  uint32_t known_build = 0;              // 该 known_rva 对应的 build 号，0 = 通用
};

// 指针失效风险：返回的是静态表的引用，进程生命周期内有效。
const std::vector<ArctiumSignatureSpec>& arctium_signature_specs();

}  // namespace wowmod
