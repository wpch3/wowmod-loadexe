// 特征自适应：拿一个"邻近 build"的特征，在用户的实际 exe 上自动放宽通配符，
// 直到得到【唯一匹配】的变体。结果仍然是数据，不写死任何版本。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/hooks.hpp"
#include "wowmod/json.hpp"

namespace wowmod {

struct AdaptResult {
  bool ok = false;
  std::string pattern;         // 最终唯一匹配的特征
  std::string source_pattern;  // 原始特征
  size_t fixed_bytes = 0;      // 保留的固定字节数（越多越可靠）
  size_t wildcard_bytes = 0;
  size_t match_count = 0;
  size_t file_offset = 0;
  uint32_t rva = 0;
  bool executable = false;     // 是否落在 PE 可执行节区
  bool warning = false;        // 原始特征 0 匹配：放宽后可能命中了别的函数，需人工核实
  std::string arch;
  std::string reason;
  Json to_json() const;
};

// 数匹配数（最多数到 cap 就停，大 exe 上更快）。offsets 可选，返回前 cap 个位置。
size_t count_matches(const Pattern& p, const std::vector<uint8_t>& haystack, size_t cap = 2,
                     std::vector<size_t>* offsets = nullptr);

// 从一条已知特征出发做自适应。min_fixed 保证结果不会退化成"全通配符"。
AdaptResult relax_pattern(const std::string& pattern_text, const std::vector<uint8_t>& exe_bytes,
                          size_t min_fixed = 8, std::string* err = nullptr);

// 把结果写成可直接使用的 patterns.json（会保留已有条目）。
struct AdaptFileResult {
  bool ok = false;
  AdaptResult adapted;
  std::string out_path;
  std::string reason;
  Json to_json() const;
};

AdaptFileResult adapt_pattern_file(const std::string& exe_path, const std::string& pattern_text,
                                   const std::string& out_path, const std::string& name,
                                   const std::string& id_register, std::string* err = nullptr);

}  // namespace wowmod
