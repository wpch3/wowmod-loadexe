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

#include <vector>

namespace wowmod {

// Arctium 的改写方式：把 patch_offset 处的 4 字节跳转条件改成 0，
// 让函数不再进入「从 CASC 加载」的分支。
struct ArctiumSignatureSpec {
  const char* name;
  const char* pattern;   // IDA 风格，?? = 通配
  int patch_offset;      // 从匹配起点到要改写的分支偏移
  const char* note;
};

// 指针失效风险：返回的是静态表的引用，进程生命周期内有效。
const std::vector<ArctiumSignatureSpec>& arctium_signature_specs();

}  // namespace wowmod
