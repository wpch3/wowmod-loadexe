// 在【目标进程】的内存里做分析并写报告 —— 全程不加载任何模块。
//
// 之前这些活是 wowmod_rt.dll 在进程内干的，但客户端会因模块表多出陌生 DLL
// 报 0x1100。现在改成启动器远程读内存，在本地做分析：
//   1. VirtualQueryEx 枚举区域 -> ReadProcessMemory 取回来
//   2. 在启动器进程里跑 analyze_image（同一份代码，只是数据来自远端）
//   3. 报告写到 <游戏>\wowmod\wowmod-analysis.txt / .json
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wowmod {
namespace win {

struct RemoteImagePick {
  uint64_t base = 0;
  size_t size = 0;
  size_t marker_hits = 0;
  std::string first_marker;
  std::string module_name;
  bool ok = false;
  std::string note;
};

// 在目标进程里找出含 loose-file 标记字符串的那块内存，并整块读回本地。
RemoteImagePick fetch_client_image(HANDLE process, std::vector<uint8_t>* out, size_t max_bytes,
                                   std::string* log);

// 探测目标进程是否允许我们分配可执行内存 / 写入。
// 这是判断"后续能否真的装 hook"的关键前提：
// 有些客户端会把非映像区域的 RX 页拦掉，那样就只剩 VFS/文件层方案。
struct WriteProbe {
  bool alloc_rw = false;       // VirtualAllocEx PAGE_READWRITE
  bool alloc_rx = false;       // VirtualAllocEx PAGE_EXECUTE_READ
  bool write_ok = false;       // WriteProcessMemory 到目标进程自己的可写页
  bool protect_ok = false;     // VirtualProtectEx 改保护属性
  std::string detail;
};
WriteProbe probe_write_capability(HANDLE process);

// 针对真实 hook 目标页做只读探测（改保护后立刻改回），
// 用于在安装前就诊断出"跨页 / 不可改保护"这类问题。
std::string probe_target_page(HANDLE process, uint64_t target, size_t need);

// 对取回的映像做分析并把报告写到 out_dir。
// 返回 0 表示成功。
int analyze_remote_and_write(HANDLE process, const std::string& out_dir, std::string* log);

}  // namespace win
}  // namespace wowmod
#endif
