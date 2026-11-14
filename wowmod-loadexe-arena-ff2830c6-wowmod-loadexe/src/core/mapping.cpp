// SPDX-License-Identifier: MIT
#include "wowmod/mapping.hpp"

namespace wowmod {

void MappingTable::add(uint64_t id, const std::string& path, const std::string& source) {
  if (path.empty()) return;
  std::string key = path_key(path);
  by_id_[id].push_back(normalize_path(path));
  auto it = by_path_.find(key);
  if (it == by_path_.end()) by_path_[key] = id;
  (void)source;
}

size_t MappingTable::parse(const std::string& text, const std::string& source, Diagnostics* diag) {
  size_t ok = 0, skipped = 0;
  sources_.push_back(source);
  std::string body = text;
  // UTF-8 BOM
  if (body.size() >= 3 && static_cast<unsigned char>(body[0]) == 0xEF && static_cast<unsigned char>(body[1]) == 0xBB && static_cast<unsigned char>(body[2]) == 0xBF) body.erase(0, 3);
  for (const auto& raw : split(replace_all(body, "\r\n", "\n"), '\n')) {
    std::string line = trim(raw);
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    // 支持 "id;path" 以及 "id;path;extra..."，id 也可以写成 0x...
    auto parts = split(line, ';');
    if (parts.size() < 2) { ++skipped; continue; }
    uint64_t id = 0;
    if (!parse_u64(trim(parts[0]), &id, 10) || id == 0) { ++skipped; continue; }
    std::string path = trim(parts[1]);
    if (path.empty()) { ++skipped; continue; }
    // 有些 listfile 带引号
    if (path.size() >= 2 && path.front() == '"' && path.back() == '"') path = path.substr(1, path.size() - 2);
    add(id, path, source);
    ++ok;
  }
  if (skipped && diag) diag->warn(source, "跳过 " + std::to_string(skipped) + " 行无法解析的映射");
  if (ok == 0 && diag) diag->warn(source, "没有解析到任何映射行（格式应为 fileId;filePath）");
  return ok;
}

bool MappingTable::load_file(const std::string& path, Diagnostics* diag) {
  std::string text, err;
  if (!read_text_file(path, &text, &err)) {
    if (diag) diag->error(path, err);
    return false;
  }
  size_t n = parse(text, path, diag);
  if (diag) diag->info(path, "载入 " + std::to_string(n) + " 条映射，累计 " + std::to_string(by_path_.size()) + " 个唯一路径");
  return true;
}

std::optional<uint64_t> MappingTable::id_for_path(const std::string& game_path) const {
  auto it = by_path_.find(path_key(game_path));
  if (it == by_path_.end()) return std::nullopt;
  return it->second;
}

std::optional<std::string> MappingTable::path_for_id(uint64_t id) const {
  auto it = by_id_.find(id);
  if (it == by_id_.end() || it->second.empty()) return std::nullopt;
  return it->second.front();
}

std::vector<std::string> MappingTable::paths_for_id(uint64_t id) const {
  auto it = by_id_.find(id);
  return it == by_id_.end() ? std::vector<std::string>{} : it->second;
}

}  // namespace wowmod
