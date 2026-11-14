// SPDX-License-Identifier: MIT
#include "wowmod/vfs.hpp"

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace wowmod {

namespace {

bool better(const OverlayHit& a, const OverlayHit& b) {
  if (a.priority != b.priority) return a.priority > b.priority;
  return a.order > b.order;
}

std::string patch_config_wtf(const std::string& original, const std::string& portal, const std::string& realmlist) {
  std::string out;
  bool replaced = false;
  for (const auto& raw : split(replace_all(original, "\r\n", "\n"), '\n')) {
    std::string line = raw;
    std::string t = trim(line);
    if (iequals(t.substr(0, 3), "SET")) {
      auto kv = split_ws(t.substr(3));
      if (kv.size() >= 1 && iequals(kv[0], "portal") && !portal.empty()) {
        line = "SET portal \"" + portal + "\"";
        replaced = true;
      }
    }
    out += line + "\n";
  }
  if (!portal.empty() && !replaced) out += "SET portal \"" + portal + "\"\n";
  if (!realmlist.empty()) {
    bool has = false;
    for (const auto& l : split(out, '\n')) if (iequals(trim(l).substr(0, 14), "SET realmlist")) has = true;
    if (!has) out += "SET realmlist \"" + realmlist + "\"\n";
  }
  return out;
}

}  // namespace

Json OverlayHit::to_json() const {
  Json j = Json::make_object();
  j.set("key", Json::make_string(key));
  j.set("from", Json::make_string(real_path));
  j.set("pack", Json::make_string(pack));
  j.set("via", Json::make_string(via));
  j.set("priority", Json::make_number(priority));
  j.set("size", Json::make_number(static_cast<double>(size)));
  if (file_id) j.set("fileId", Json::make_number(static_cast<double>(file_id)));
  if (generated) j.set("generated", Json::make_bool(true));
  if (blocked) j.set("blocked", Json::make_bool(true));
  if (!content.empty() && generated) j.set("content", Json::make_string(content));
  return j;
}

Json VfsStats::to_json() const {
  Json j = Json::make_object();
  j.set("packs", Json::make_number(static_cast<double>(packs)));
  j.set("packFiles", Json::make_number(static_cast<double>(pack_files)));
  j.set("overlays", Json::make_number(static_cast<double>(overlays)));
  j.set("generated", Json::make_number(static_cast<double>(generated)));
  j.set("idMappings", Json::make_number(static_cast<double>(id_mappings)));
  j.set("conflicts", Json::make_number(static_cast<double>(conflicts)));
  j.set("skippedByFilter", Json::make_number(static_cast<double>(skipped_by_filter)));
  return j;
}

bool Vfs::register_hit(OverlayHit hit) {
  if (hit.key.empty()) return false;
  if (hit.display_key.empty()) hit.display_key = normalize_path(hit.key);
  hit.key = path_key(hit.key);
  hit.real_path = normalize_path(hit.real_path);
  if (hit.size == 0 && !hit.generated && !hit.blocked) hit.size = file_size(hit.real_path);
  if (hit.order == 0) hit.order = ++order_counter_;
  auto it = by_path_.find(hit.key);
  if (it != by_path_.end()) {
    if (better(hit, it->second)) {
      it->second = hit;
      ++stats_.conflicts;
    } else {
      ++stats_.conflicts;
    }
  } else {
    by_path_[hit.key] = hit;
  }
  if (hit.file_id && !hit.blocked) {
    auto iit = by_id_.find(hit.file_id);
    if (iit == by_id_.end() || better(hit, iit->second)) by_id_[hit.file_id] = hit;
  }
  entries_.push_back(hit);
  return true;
}

std::optional<OverlayHit> Vfs::apply_rules(const std::string& key) const {
  std::optional<OverlayHit> best;
  for (const auto& r : rules_) {
    if (!r.when.matches(client_)) continue;
    if (!wildcard_match(r.match, key, true)) continue;
    OverlayHit h;
    h.key = key;
    h.via = "rule";
    h.pack = "rule:" + r.match;
    h.priority = r.priority;
    h.order = 1000000;
    if (r.replace.empty()) {
      h.blocked = true;
    } else {
      h.real_path = r.replace;
      h.size = file_size(r.replace);
    }
    if (!best || better(h, *best)) best = h;
  }
  return best;
}

bool Vfs::build(const Config& cfg, const ClientInfo& ci, const MappingTable& mappings, Diagnostics* diag) {
  cfg_ = cfg;
  client_ = ci;
  rules_ = cfg.rules;
  stats_ = VfsStats{};
  order_counter_ = 0;
  by_path_.clear();
  by_id_.clear();
  entries_.clear();
  path_to_id_.clear();
  id_to_path_.clear();
  for (const auto& kv : mappings.by_path()) path_to_id_[kv.first] = kv.second;
  for (const auto& kv : mappings.by_id()) if (!kv.second.empty()) id_to_path_[kv.first] = kv.second.front();

  size_t seq = 0;
  for (const auto& pack : cfg.mods) {
    if (!pack.enabled) continue;
    if (!pack.when.matches(ci)) {
      ++stats_.skipped_by_filter;
      if (diag) diag->info("vfs", "模组包 [" + pack.name + "] 的适用范围与当前客户端不匹配，跳过");
      continue;
    }
    ++stats_.packs;
    std::string scan_root = pack.root.empty() ? pack.path : join_path(pack.path, pack.root);

    // 先解析清单，收集被清单引用的本地文件（扫描目录时跳过它们，避免出现无意义的 "override.blp" 覆盖项）
    struct ManifestEntry { uint64_t id = 0; std::string key; std::string local; };
    std::vector<ManifestEntry> manifest;
    std::unordered_set<std::string> referenced;
    std::string manifest_path = pack.manifest;
    if (manifest_path.empty()) manifest_path = join_path(pack.path, "wowmod.manifest.json");
    std::string mtext;
    if (file_exists(manifest_path) && read_text_file(manifest_path, &mtext, nullptr)) {
      std::string perr;
      Json mj = Json::parse(mtext, &perr);
      if (perr.empty()) {
        for (const auto& f : mj.at("files").as_array()) {
          ManifestEntry e;
          e.id = static_cast<uint64_t>(f.at("id").as_int(0));
          e.key = f.at("path").as_string();
          e.local = f.at("file").as_string();
          if (e.local.empty() || (e.id == 0 && e.key.empty())) continue;
          // 只给 id 时，用 listfile 反查真实游戏路径（不依赖版本）
          if (e.key.empty()) {
            auto p = mappings.path_for_id(e.id);
            e.key = p ? *p : ("#" + std::to_string(e.id));
          }
          manifest.push_back(e);
          referenced.insert(path_key(e.local));
        }
      } else if (diag) diag->warn(manifest_path, perr);
    }

    std::string err;
    auto files = list_files_recursive(scan_root, &err);
    if (files.empty() && !err.empty()) {
      if (diag) diag->error("vfs", err);
    }
    for (const auto& rel : files) {
      std::string name = file_name(rel);
      if (name == "wowmod.manifest.json" || name == "wowmod.json" || starts_with(name, ".")) continue;
      // 模组包根目录的说明文档不是游戏资源
      std::string lname = to_lower(name);
      if (parent_path(rel).empty() &&
          (iequals(file_extension(rel), ".md") || starts_with(lname, "readme") ||
           starts_with(lname, "license") || starts_with(lname, "changelog"))) continue;
      if (referenced.count(path_key(rel))) continue;
      ++stats_.pack_files;
      OverlayHit h;
      h.key = rel;
      h.real_path = join_path(scan_root, rel);
      h.pack = pack.name;
      h.via = "path";
      h.priority = pack.priority;
      h.order = ++seq;
      auto id = mappings.id_for_path(rel);
      if (id) { h.file_id = *id; ++stats_.id_mappings; }
      register_hit(std::move(h));
    }

    for (const auto& e : manifest) {
      OverlayHit h;
      h.key = e.key;
      h.real_path = join_path(pack.path, e.local);
      h.pack = pack.name;
      h.via = "manifest";
      h.priority = pack.priority + 1;
      h.order = ++seq;
      h.file_id = e.id;
      if (h.file_id == 0) { auto i = mappings.id_for_path(e.key); if (i) h.file_id = *i; }
      if (h.file_id) ++stats_.id_mappings;
      register_hit(std::move(h));
    }
  }

  // 内存生成文件：portal / realmlist（不修改磁盘上的游戏文件）
  if (!cfg.client.portal.empty() || !cfg.client.realmlist.empty()) {
    std::string original;
    read_text_file(join_path(ci.game_dir, "WTF/Config.wtf"), &original, nullptr);
    std::string content = patch_config_wtf(original, cfg.client.portal, cfg.client.realmlist);
    OverlayHit h;
    h.key = "wtf/config.wtf";
    h.pack = "generated";
    h.via = "generated";
    h.generated = true;
    h.priority = 10000;
    h.order = ++seq;
    h.content = content;
    h.size = content.size();
    register_hit(std::move(h));
    ++stats_.generated;
  }
  if (!cfg.client.realmlist.empty()) {
    // 老客户端读 realmlist.wtf；若磁盘上存在则覆盖它，否则新增一个。
    std::string target = "realmlist.wtf";
    for (const auto& candidate : {"Data/realmlist.wtf", "realmlist.wtf", "Data/enUS/realmlist.wtf", "Data/zhCN/realmlist.wtf"}) {
      if (file_exists(join_path(ci.game_dir, candidate))) { target = candidate; break; }
    }
    OverlayHit h;
    h.key = target;
    h.pack = "generated";
    h.via = "generated";
    h.generated = true;
    h.priority = 10000;
    h.order = ++seq;
    h.content = "set realmlist " + cfg.client.realmlist + "\n";
    h.size = h.content.size();
    register_hit(std::move(h));
    ++stats_.generated;
  }

  // 规则（高优先级，resolve 时动态生效；这里只统计）
  stats_.overlays = by_path_.size() + by_id_.size();
  if (diag) {
    diag->info("vfs", "覆盖表构建完成: " + std::to_string(by_path_.size()) + " 个路径, " +
                          std::to_string(by_id_.size()) + " 个 FileDataID, " +
                          std::to_string(stats_.generated) + " 个内存生成文件");
    if (stats_.conflicts) diag->info("vfs", std::to_string(stats_.conflicts) + " 处覆盖冲突已按优先级裁决");
  }
  return true;
}

std::optional<OverlayHit> Vfs::resolve_path(const std::string& game_relative_path) const {
  std::string key = path_key(game_relative_path);
  if (auto r = apply_rules(key)) return r;  // 包括 blocked
  auto it = by_path_.find(key);
  if (it != by_path_.end()) return it->second;
  // 尝试 listfile: 路径 -> id -> 由 id 注册的覆盖
  auto id = mappings_id_for_path(key);
  if (id) {
    auto iit = by_id_.find(*id);
    if (iit != by_id_.end()) return iit->second;
  }
  return std::nullopt;
}

std::optional<OverlayHit> Vfs::resolve_id(uint64_t file_id) const {
  auto it = by_id_.find(file_id);
  if (it != by_id_.end()) return it->second;
  // id -> 路径 -> 路径覆盖
  auto path = mappings_path_for_id(file_id);
  if (path) return resolve_path(*path);
  return std::nullopt;
}

std::optional<OverlayHit> Vfs::resolve_any(const std::string& key) const {
  std::string t = trim(key);
  if (!t.empty() && t[0] == '#') t.erase(0, 1);
  uint64_t id = 0;
  if (parse_u64(t, &id, 10)) return resolve_id(id);
  return resolve_path(t);
}

std::vector<std::string> Vfs::extra_names(const std::string& dir_key) const {
  std::string dir = path_key(dir_key);
  while (!dir.empty() && dir.back() == '/') dir.pop_back();
  std::string prefix = dir.empty() ? "" : dir + "/";
  size_t dir_segments = dir.empty() ? 0 : split(dir, '/').size();
  std::vector<std::string> out;
  for (const auto& kv : by_path_) {
    const std::string& key = kv.first;
    if (!prefix.empty() && !starts_with(key, prefix)) continue;
    std::string rel = prefix.empty() ? key : key.substr(prefix.size());
    if (rel.empty()) continue;
    // 只报告"新增"条目（磁盘上原本不存在）；已有的文件直接走路径替换
    std::string real = join_path(client_.game_dir, key);
    if (file_exists(real)) continue;
    // 保留原始大小写：从 display_key 里取对应层级的第一段
    const std::string& disp = kv.second.display_key;
    auto segs = split(disp, '/');
    std::string name;
    if (segs.size() > dir_segments) name = segs[dir_segments];
    if (name.empty()) name = file_name(rel);
    out.push_back(name);
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

std::vector<OverlayHit> Vfs::effective_entries() const {
  std::vector<OverlayHit> out;
  for (const auto& kv : by_path_) out.push_back(kv.second);
  for (const auto& kv : by_id_) {
    if (by_path_.find(kv.second.key) == by_path_.end()) out.push_back(kv.second);
  }
  return out;
}

std::vector<OverlayHit> Vfs::generated_entries() const {
  std::vector<OverlayHit> out;
  for (const auto& h : entries_) if (h.generated) out.push_back(h);
  return out;
}

size_t Vfs::materialize_generated(const std::string& temp_dir, Diagnostics* diag) {
  size_t n = 0;
  for (auto& h : by_path_) {
    if (!h.second.generated || h.second.content.empty()) continue;
    std::string target = join_path(temp_dir, h.second.key);
    std::string err;
    if (write_text_file(target, h.second.content, &err)) {
      h.second.real_path = target;
      h.second.size = h.second.content.size();
      ++n;
    } else if (diag) diag->warn("vfs", err);
  }
  for (auto& h : by_id_) {
    if (!h.second.generated || h.second.content.empty()) continue;
    std::string target = join_path(temp_dir, h.second.key);
    std::string err;
    if (write_text_file(target, h.second.content, &err)) {
      h.second.real_path = target;
      h.second.size = h.second.content.size();
    }
  }
  for (auto& h : entries_) {
    if (!h.generated || h.content.empty()) continue;
    h.real_path = join_path(temp_dir, h.key);
  }
  if (diag) diag->info("vfs", "已生成 " + std::to_string(n) + " 个内存文件到 " + temp_dir);
  return n;
}

std::string Vfs::plan_text() const {
  std::ostringstream os;
  os << "覆盖表 (" << by_path_.size() << " 条路径 / " << by_id_.size() << " 个 FileDataID)\n";
  std::vector<OverlayHit> sorted = effective_entries();
  std::sort(sorted.begin(), sorted.end(), [](const OverlayHit& a, const OverlayHit& b) {
    if (a.priority != b.priority) return a.priority > b.priority;
    return a.key < b.key;
  });
  for (const auto& h : sorted) {
    os << "  [" << h.priority << "] " << h.key;
    if (h.file_id) os << "  (#" << h.file_id << ")";
    os << "\n        <- " << (h.generated ? "(内存生成)" : h.real_path) << "  [" << h.pack << "/" << h.via << "]\n";
  }
  if (sorted.empty()) os << "  (空)\n";
  return os.str();
}

Json Vfs::plan_json() const {
  Json j = Json::make_object();
  j.set("client", client_.to_json());
  j.set("stats", stats_.to_json());
  Json arr = Json::make_array();
  std::vector<OverlayHit> sorted = effective_entries();
  std::sort(sorted.begin(), sorted.end(), [](const OverlayHit& a, const OverlayHit& b) { return a.key < b.key; });
  for (const auto& h : sorted) arr.push(h.to_json());
  j.set("overlays", arr);
  Json rules = Json::make_array();
  for (const auto& r : rules_) {
    Json o = Json::make_object();
    o.set("match", Json::make_string(r.match));
    o.set("replace", Json::make_string(r.replace));
    rules.push(o);
  }
  j.set("rules", rules);
  return j;
}

std::optional<uint64_t> Vfs::mappings_id_for_path(const std::string& key) const {
  auto it = path_to_id_.find(path_key(key));
  return it == path_to_id_.end() ? std::nullopt : std::optional<uint64_t>(it->second);
}

std::optional<std::string> Vfs::mappings_path_for_id(uint64_t id) const {
  auto it = id_to_path_.find(id);
  return it == id_to_path_.end() ? std::nullopt : std::optional<std::string>(it->second);
}

}  // namespace wowmod
