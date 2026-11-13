// 虚拟文件系统覆盖层：把"游戏要打开的路径 / FileDataID"映射到模组文件。
// 这一层不碰客户端内部函数，所以对任何版本都有效。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "wowmod/config.hpp"
#include "wowmod/json.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/version.hpp"

namespace wowmod {

struct OverlayHit {
  std::string key;          // 小写规范化后的 game-relative 路径（查找用）
  std::string display_key;  // 保留原始大小写（目录枚举/展示用）
  std::string real_path;    // 实际磁盘路径
  std::string pack;       // 来源（模组名 / "generated" / "rule"）
  std::string via;        // path | manifest | rule | generated | id
  int priority = 0;
  size_t order = 0;       // 同优先级时后加载者优先
  uint64_t file_id = 0;
  uint64_t size = 0;
  bool generated = false;
  bool blocked = false;
  std::string content;    // generated 文件的内容

  Json to_json() const;
};

struct VfsStats {
  size_t packs = 0, pack_files = 0, overlays = 0, generated = 0, id_mappings = 0;
  size_t conflicts = 0, skipped_by_filter = 0;
  Json to_json() const;
};

class Vfs {
 public:
  // 根据配置 + 探测到的客户端 + listfile 构建覆盖表。永远不因版本未知而失败。
  bool build(const Config& cfg, const ClientInfo& ci, const MappingTable& mappings, Diagnostics* diag = nullptr);

  std::optional<OverlayHit> resolve_path(const std::string& game_relative_path) const;
  std::optional<OverlayHit> resolve_id(uint64_t file_id) const;
  // path 或 "#12345" / 纯数字，供 hook 层使用
  std::optional<OverlayHit> resolve_any(const std::string& key) const;

  // 目录枚举叠加：返回该目录下"新增的"文件名（原本不存在的覆盖项）。
  std::vector<std::string> extra_names(const std::string& dir_key) const;

  const std::vector<OverlayHit>& entries() const { return entries_; }
  // 冲突裁决后的最终覆盖表（每个 key 只保留胜出者）
  std::vector<OverlayHit> effective_entries() const;
  std::vector<OverlayHit> generated_entries() const;
  const VfsStats& stats() const { return stats_; }
  const ClientInfo& client() const { return client_; }

  // 把内存生成的文件写到私有临时目录，并把 real_path 指向它们（Windows 注入端调用）。
  size_t materialize_generated(const std::string& temp_dir, Diagnostics* diag = nullptr);

  // 生成可读的启动计划文本。
  std::string plan_text() const;
  Json plan_json() const;

 private:
  bool register_hit(OverlayHit hit);
  std::optional<OverlayHit> apply_rules(const std::string& key) const;
  std::optional<uint64_t> mappings_id_for_path(const std::string& key) const;
  std::optional<std::string> mappings_path_for_id(uint64_t id) const;

  size_t order_counter_ = 0;
  std::map<std::string, uint64_t> path_to_id_;
  std::map<uint64_t, std::string> id_to_path_;
  std::map<std::string, OverlayHit> by_path_;
  std::map<uint64_t, OverlayHit> by_id_;
  std::vector<OverlayHit> entries_;
  std::vector<Rule> rules_;
  ClientInfo client_;
  Config cfg_;
  VfsStats stats_;
};

}  // namespace wowmod
