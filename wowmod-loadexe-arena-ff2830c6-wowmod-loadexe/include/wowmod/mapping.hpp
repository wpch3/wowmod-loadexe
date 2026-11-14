// FileDataID <-> 路径 映射表（wow-listfile 格式: "fileId;filePath"）。
// 映射是数据，不是内置表：任何版本/私服的 listfile 都可以直接丢进来。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "wowmod/util.hpp"

namespace wowmod {

class MappingTable {
 public:
  // 成功解析的行数；错误写入 Diagnostics（warn），不因单行错误整体失败。
  size_t parse(const std::string& text, const std::string& source, Diagnostics* diag = nullptr);
  bool load_file(const std::string& path, Diagnostics* diag = nullptr);
  void add(uint64_t id, const std::string& path, const std::string& source);

  std::optional<uint64_t> id_for_path(const std::string& game_path) const;
  std::optional<std::string> path_for_id(uint64_t id) const;
  std::vector<std::string> paths_for_id(uint64_t id) const;
  const std::unordered_map<std::string, uint64_t>& by_path() const { return by_path_; }
  const std::unordered_map<uint64_t, std::vector<std::string>>& by_id() const { return by_id_; }
  size_t size() const { return by_path_.size(); }

 private:
  std::unordered_map<uint64_t, std::vector<std::string>> by_id_;
  std::unordered_map<std::string, uint64_t> by_path_;
  std::vector<std::string> sources_;
};

}  // namespace wowmod
