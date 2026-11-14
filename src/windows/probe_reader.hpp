// 读取目标进程里的旁路记录环形缓冲，转成可读日志。
//
// 为什么要单独做成一个模块：
//   跳板只负责「把 id 记进环形缓冲」，不做任何格式化或 I/O —— 在客户端主线程里
//   调文件 API 是自杀行为（重入、锁、堆）。所以数据留在内存，由我们这一侧
//   按 total 的增量把新记录读出来写盘。这样即使读得慢，也只是丢记录（有 dropped
//   计数可查），不会拖慢或弄坏客户端。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/probe_stub.hpp"

namespace wowmod {
namespace win {

struct ProbeRecord {
  uint32_t id = 0;
  uint32_t seq = 0;
};

// 从目标进程读出「自上次读取以来新增」的记录。
//   last_seq —— 调用方保存的上次最大序号，首次传 0；函数会就地更新。
// 返回 false 时 err 给出原因（缓冲区不可读 / magic 不符 / 还没写入任何记录）。
bool read_probe_records(HANDLE process, uint64_t buffer_va, uint32_t capacity,
                        uint32_t* last_seq, std::vector<ProbeRecord>* out, std::string* err);

// 把一批记录追加进日志文件。按 id 聚合统计，并保留前 N 条原始序列。
// 返回写入的字节数（0 表示没写）。
size_t append_probe_log(const std::string& path, const std::vector<ProbeRecord>& records,
                        uint32_t total_seen, bool truncate);

// 统计聚合：id -> 出现次数。
std::vector<std::pair<uint32_t, uint32_t>> summarize(const std::vector<ProbeRecord>& records);

}  // namespace win
}  // namespace wowmod
#endif
