// 可选 CASC 适配层：用 CPU 硬件断点 + VEH 在客户端"按 FileDataID 读文件"的函数入口
// 短路返回模组文件路径。不修改客户端任何字节的代码，因此不会因版本变化而打补丁失败。
// hook 点来自外部 patterns.json 在实际 exe 上的唯一匹配。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#include <string>

#include "wowmod/hooks.hpp"

namespace wowmod {
namespace win {

// 返回是否成功安装；失败时调用方继续用纯 VFS 模式，绝不阻止启动。
bool install_fileid_hook(const HookPlan& plan, std::string* err);

}  // namespace win
}  // namespace wowmod
#endif
