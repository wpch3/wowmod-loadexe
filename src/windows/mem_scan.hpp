// 运行时内存扫描：针对「磁盘上 .text 被加密、运行时才解密」的私服客户端。
// 注入 DLL 在进程内把已解密的模块映像拷出来，做字符串/引用发现，产出候选特征。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#include <string>
#include <vector>

#include "wowmod/discover.hpp"

namespace wowmod {
namespace win {

// 把某个已加载模块的内存映像（文件偏移 == RVA）写到磁盘，未提交页面填 0。
// module 为空 = 主 exe；否则为 DLL 名。返回 false 时 err 有原因。
bool dump_module_image(const std::string& module, const std::string& out_path,
                       std::vector<uint8_t>* image, std::string* err);

// 后台线程入口：等待壳解密 -> 转储各模块 -> 内存映像上做 discover -> 写报告。
// 绝不阻塞 DllMain；失败只记日志，不影响客户端启动。
void start_runtime_scan();

}  // namespace win
}  // namespace wowmod
#endif
