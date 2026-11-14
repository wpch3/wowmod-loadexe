// 旁路记录缓冲的读取与落盘实现。
// SPDX-License-Identifier: MIT
#include "windows/probe_reader.hpp"
#ifdef _WIN32

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

bool read_probe_records(HANDLE process, uint64_t buffer_va, uint32_t capacity,
                        uint32_t* last_seq, std::vector<ProbeRecord>* out, std::string* err) {
  if (!process || !buffer_va || !last_seq || !out) {
    if (err) *err = "参数为空";
    return false;
  }
  out->clear();

  // 只读头部，确认 magic 与总量 —— 头部读不动就没必要读槽位了。
  uint8_t head[ProbeBufferLayout::kSlotsOff];
  SIZE_T got = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<const void*>(buffer_va), head, sizeof(head),
                         &got) ||
      got != sizeof(head)) {
    if (err) *err = "读环形缓冲头部失败, GetLastError=" + std::to_string(GetLastError());
    return false;
  }
  uint32_t magic = 0, cap = 0, headidx = 0, total = 0;
  std::memcpy(&magic, head + ProbeBufferLayout::kMagicOff, 4);
  std::memcpy(&cap, head + ProbeBufferLayout::kCapacityOff, 4);
  std::memcpy(&headidx, head + ProbeBufferLayout::kHeadOff, 4);
  std::memcpy(&total, head + ProbeBufferLayout::kTotalOff, 4);
  if (magic != ProbeBufferLayout::kMagic) {
    if (err) *err = "环形缓冲 magic 不符（跳板可能没被执行过）";
    return false;
  }
  if (cap != capacity) {
    if (err) *err = "环形缓冲容量与预期不符（内存里的旧版本？）";
    return false;
  }
  if (total == 0) {
    if (err) *err = "还没有任何记录（目标函数尚未被调用）";
    return false;
  }
  if (total <= *last_seq) {
    if (err) *err = "没有新记录";
    return false;
  }
  (void)headidx;

  // 只读新增的那一段。如果新增量超过容量，说明我们读得太慢，
  // 那就只把容量上限内的这一圈读出来，并在日志里注明。
  uint32_t fresh = total - *last_seq;
  const uint32_t to_read = std::min(fresh, cap);
  const uint32_t first_seq = total - to_read + 1;

  // 首条对应的槽位号
  const uint32_t first_slot = (headidx + cap - to_read) & (cap - 1);
  for (uint32_t i = 0; i < to_read; ++i) {
    const uint32_t slot = (first_slot + i) & (cap - 1);
    const uint64_t at = buffer_va + ProbeBufferLayout::kSlotsOff +
                        static_cast<uint64_t>(slot) * ProbeBufferLayout::kSlotStride;
    uint8_t raw[ProbeBufferLayout::kSlotStride];
    SIZE_T g = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(at), raw, sizeof(raw), &g) ||
        g != sizeof(raw)) {
      continue;  // 单个槽位读失败就跳过，不整体失败
    }
    uint64_t id = 0;
    uint32_t seq = 0;
    std::memcpy(&id, raw + ProbeBufferLayout::kSlotIdOff, 8);
    std::memcpy(&seq, raw + ProbeBufferLayout::kSlotSeqOff, 4);
    // seq == 0 表示这个槽位本轮还没被写过（我们会跳过）
    if (seq == 0) continue;
    if (seq < first_seq) continue;  // 被覆盖过的旧数据
    ProbeRecord r;
    r.id = static_cast<uint32_t>(id);
    r.seq = seq;
    out->push_back(r);
  }
  *last_seq = total;
  return true;
}

std::vector<std::pair<uint32_t, uint32_t>> summarize(const std::vector<ProbeRecord>& records) {
  std::map<uint32_t, uint32_t> m;
  for (const auto& r : records) m[r.id]++;
  std::vector<std::pair<uint32_t, uint32_t>> v(m.begin(), m.end());
  // 出现次数多的排前面 —— 高频 id 通常就是被反复加载的模型/贴图。
  std::stable_sort(v.begin(), v.end(),
                   [](const std::pair<uint32_t, uint32_t>& a,
                      const std::pair<uint32_t, uint32_t>& b) {
                     if (a.second != b.second) return a.second > b.second;
                     return a.first < b.first;
                   });
  return v;
}

size_t append_probe_log(const std::string& path, const std::vector<ProbeRecord>& records,
                        uint32_t total_seen, bool truncate) {
  if (path.empty()) return 0;
  FILE* f = nullptr;
  if (_wfopen_s(&f, utf8_to_wide(path).c_str(), truncate ? L"wb" : L"ab") != 0 || !f) return 0;
  size_t written = 0;
  if (truncate) {
    const std::string hdr =
        "\xEF\xBB\xBF"  // UTF-8 BOM，方便记事本直接打开
        "wowmod 旁路记录 —— FileDataID 真实调用序列\n"
        "说明：这是 hook 到 CAS.cpp 的 FileDataID 查找函数后，客户端实际传入的 edx 值。\n"
        "      本项目没有修改任何返回值，记录的是原始行为。\n"
        "\n== 调用序列（按发生顺序）==\n";
    written += fwrite(hdr.data(), 1, hdr.size(), f);
  }
  char buf[128];
  for (const auto& r : records) {
    const int n = std::snprintf(buf, sizeof(buf), "seq=%u  id=%u  (0x%08X)\n", r.seq, r.id, r.id);
    if (n > 0) written += fwrite(buf, 1, static_cast<size_t>(n), f);
  }
  if (truncate || !records.empty()) {
    const auto agg = summarize(records);
    const int n = std::snprintf(buf, sizeof(buf), "\n累计调用次数: %u\n", total_seen);
    if (n > 0) written += fwrite(buf, 1, static_cast<size_t>(n), f);
    for (const auto& kv : agg) {
      const int m = std::snprintf(buf, sizeof(buf), "  id=%-10u x%u\n", kv.first, kv.second);
      if (m > 0) written += fwrite(buf, 1, static_cast<size_t>(m), f);
    }
  }
  fclose(f);
  return written;
}

}  // namespace win
}  // namespace wowmod
#endif
