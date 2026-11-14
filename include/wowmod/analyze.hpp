// 从「真实解密后的客户端映像」推导 loose-file hook 方案。
//
// 这是整个方案里唯一不依赖版本号的部分：不问 build 号、不查特征表，
// 而是找客户端自己会用到的东西 —— 它打印 "Locally overridden files" 的那个地方、
// 以及它按 FileDataID 查表的那个函数。
//
// 输出是一份可审计的 JSON：候选函数 RVA、完整指令边界的 hook 点、
// 需要搬运多少字节、猜测的 FileDataID 寄存器，以及"证据强度"。
// 最终是否打补丁由调用方（人）决定，或由运行期观察结果确认。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "wowmod/json.hpp"
#include "wowmod/xref.hpp"

namespace wowmod {

// 客户端自己会打印/引用的、与本地文件覆盖相关的字符串。
// 这些字符串是版本无关的：只要客户端还支持 loose 文件和 FileDataID 日志，
// 它们就会存在。按可信度从高到低排列。
struct LooseFileMarker {
  std::string text;
  const char* why;
  int weight;
};

const std::vector<LooseFileMarker>& loose_file_markers();

struct StringHit {
  std::string marker;
  size_t rva = 0;
  bool utf16 = false;
  std::vector<CodeRef> refs;        // 引用该字符串的 lea/mov
  std::vector<size_t> functions;    // 引用者回退出的函数起点
};

struct AnalyzeOptions {
  uint64_t base_va = 0;
  size_t max_functions = 16;
  bool scan_id_lookup = true;
  // 每个"全盘扫描"阶段的秒级预算。对 100MB+ 映像，标记数 × 命中数
  // 会让 find_code_refs_to 被调用几十次，每次都扫全图，总耗时会爆炸。
  // 设 0 表示不限制（离线 CLI 用），远程分析必须设上限。
  double refs_budget_seconds = 0.0;
  double id_budget_seconds = 0.0;
  // 进度回调：阶段名 + 已完成/总数，用于在远程分析时实时打印
  std::function<void(const std::string& stage, size_t done, size_t total)> progress;
  // 原始视图扫不到任何代码引用时，自动尝试按节表把「磁盘文件布局」
  // 重映射成「内存布局」再分析一次（结果会写在报告里，不猜）。
  bool allow_file_remap = true;
};

// 把「磁盘文件布局」的缓冲区按节表重映射成「内存布局」（raw_ptr -> va）。
// 用于自证：如果原缓冲区是文件布局，重映射之后 xref 就能找到引用了。
// 返回 false 表示不是可解析的 PE 或没有可搬的节。
bool remap_file_to_image(const ImageView& in, std::vector<uint8_t>* out);

struct AnalyzeResult {
  bool ok = false;
  std::string error;
  size_t image_size = 0;
  uint64_t base_va = 0;
  std::vector<StringHit> string_hits;
  std::vector<IdLookupCandidate> id_candidates;

  // 对每个「字符串引用所在的函数起点」给出 hook 点方案
  struct Site {
    std::string marker;
    size_t function_rva = 0;
    size_t ref_rva = 0;       // 引用字符串的那条指令
    HookSitePlan site;        // 以函数起点为 hook 点的可行性与搬运长度
    std::vector<ShownInsn> function_prologue;
  };
  std::vector<Site> sites;

  // 推荐的 hook 点集合：每个「引用 loose-file 标记字符串的函数」一条独立 detour。
  // 这是最保守也最贴近语义的做法：只拦截真正会去加载本地文件的那个函数，
  // 不猜 FileDataID 查找函数、也不需要知道 id 在哪个寄存器。
  struct DetourTarget {
    std::string marker;
    size_t function_rva = 0;
    bool hookable = false;
    size_t copy_len = 0;
    std::string reason;
  };
  std::vector<DetourTarget> detour_targets;

  // 布局判定 + 未命中引用的字符串（照样报出来，只是标记为"无代码引用"）。
  // 之前这些被静默丢弃，报告里就变成"没有找到任何标记字符串"，
  // 与「命中标记: 5 个」自相矛盾，把排查带偏了。
  // 是否靠「文件布局重映射」才拿到引用（真客户端大概率为 true）
  bool used_file_remap = false;
  struct OrphanString {
    std::string marker;
    size_t rva = 0;
    bool utf16 = false;
  };
  std::vector<OrphanString> orphan_strings;

  Json to_json() const;
  std::string to_text() const;
};

AnalyzeResult analyze_image(const ImageView& img, const AnalyzeOptions& opt = {});

// 便捷：从文件读入映像（例如运行期导出的 *.img）。
AnalyzeResult analyze_image_file(const std::string& path, uint64_t base_va,
                                 const AnalyzeOptions& opt = {});

// 把磁盘 PE 展开成「按内存映像布局」的缓冲区（文件偏移 == RVA）。
// 运行时转储（*.img）已经是这个布局，不要对它们再调用本函数。
// 这样 analyze/xref/site 就能同时用于磁盘 exe 和内存转储。
bool map_pe_image(const std::vector<uint8_t>& file, std::vector<uint8_t>* out,
                  uint64_t* base_va, std::string* err);

// 统一加载：--mapped 时原样使用；否则若解析出是 PE，就展开成映像布局。
bool load_analysis_image(const std::string& path, bool already_mapped,
                         std::vector<uint8_t>* out, uint64_t* base_va, std::string* err);

}  // namespace wowmod
