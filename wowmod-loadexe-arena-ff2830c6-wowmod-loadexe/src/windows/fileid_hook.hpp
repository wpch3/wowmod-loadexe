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

// 运行时内存扫描发现 hook 点后直接安装（module 为空 = 主 exe）。
// 特征来自运行时的实际内存，不依赖磁盘文件是否被加密。
bool install_runtime_fileid_hook(const std::string& module, uint32_t rva,
                                 const std::string& pattern, const std::string& id_register,
                                 std::string* err);

}  // namespace win
}  // namespace wowmod
#endif
