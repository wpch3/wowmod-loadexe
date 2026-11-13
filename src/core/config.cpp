// SPDX-License-Identifier: MIT
#include "wowmod/config.hpp"

#include <algorithm>

namespace wowmod {

namespace {

std::vector<std::string> strings_from(const Json& j) {
  std::vector<std::string> out;
  if (j.type != Json::Type::Array) return out;
  for (const auto& v : j.as_array()) {
    std::string s = v.as_string();
    if (!s.empty()) out.push_back(s);
  }
  return out;
}

std::string resolve(const std::string& base, const std::string& p) {
  std::string t = trim(p);
  if (t.empty()) return "";
  return is_absolute_path(t) ? normalize_path(t) : join_path(base, t);
}

}  // namespace

bool When::any() const {
  return builds.empty() && min_build == 0 && max_build == 0 && products.empty() && storage.empty() && arch.empty();
}

bool When::matches(const ClientInfo& ci) const {
  if (any()) return true;
  if (!builds.empty() && std::find(builds.begin(), builds.end(), ci.build) == builds.end()) return false;
  if (min_build > 0 && ci.build > 0 && ci.build < min_build) return false;
  if (max_build > 0 && ci.build > 0 && ci.build > max_build) return false;
  auto in = [](const std::vector<std::string>& v, const std::string& s) {
    return std::any_of(v.begin(), v.end(), [&](const std::string& x) { return iequals(x, s); });
  };
  if (!products.empty() && !in(products, ci.product)) return false;
  if (!storage.empty() && !in(storage, ci.storage)) return false;
  if (!arch.empty() && !in(arch, ci.arch)) return false;
  return true;
}

When When::from_json(const Json& j) {
  When w;
  if (j.type != Json::Type::Object) return w;
  for (const auto& b : j.at("builds").as_array()) w.builds.push_back(static_cast<int>(b.as_int(0)));
  w.min_build = static_cast<int>(j.at("minBuild").as_int(0));
  w.max_build = static_cast<int>(j.at("maxBuild").as_int(0));
  w.products = strings_from(j.at("products"));
  w.storage = strings_from(j.at("storage"));
  w.arch = strings_from(j.at("arch"));
  return w;
}

Json When::to_json() const {
  Json j = Json::make_object();
  if (!builds.empty()) { Json a = Json::make_array(); for (int b : builds) a.push(Json::make_number(b)); j.set("builds", a); }
  if (min_build) j.set("minBuild", Json::make_number(min_build));
  if (max_build) j.set("maxBuild", Json::make_number(max_build));
  auto arr = [](const std::vector<std::string>& v) { Json a = Json::make_array(); for (const auto& s : v) a.push(Json::make_string(s)); return a; };
  if (!products.empty()) j.set("products", arr(products));
  if (!storage.empty()) j.set("storage", arr(storage));
  if (!arch.empty()) j.set("arch", arr(arch));
  return j;
}

Config Config::from_json(const Json& j, const std::string& config_path, Diagnostics* diag) {
  Config c;
  c.path = absolute_path(config_path);
  c.base_dir = parent_path(c.path);
  c.version = static_cast<int>(j.at("version").as_int(1));

  const Json& cl = j.at("client");
  c.client.exe = resolve(c.base_dir, cl.at("exe").as_string());
  c.client.game_dir = resolve(c.base_dir, cl.at("gameDir").as_string());
  c.client.portal = cl.at("portal").as_string();
  c.client.realmlist = cl.at("realmlist").as_string();
  c.client.args = strings_from(cl.at("args"));
  c.client.clear_cache = cl.at("clearCache").as_bool(false);

  const Json& mods = j.at("mods");
  for (const auto& m : mods.as_array()) {
    ModPack p;
    p.name = m.at("name").as_string();
    p.path = resolve(c.base_dir, m.at("path").as_string());
    p.root = m.at("root").as_string();
    p.manifest = resolve(c.base_dir, m.at("manifest").as_string());
    p.enabled = m.at("enabled").as_bool(true);
    p.priority = static_cast<int>(m.at("priority").as_int(0));
    p.when = When::from_json(m.at("when"));
    if (p.name.empty()) p.name = file_name(p.path);
    c.mods.push_back(p);
  }

  for (const auto& s : strings_from(j.at("mappings"))) {
    c.mappings.push_back(resolve(c.base_dir, s));
  }

  const Json& rules = j.at("rules");
  for (const auto& r : rules.as_array()) {
    Rule rule;
    rule.match = r.at("match").as_string();
    rule.replace = resolve(c.base_dir, r.at("replace").as_string());
    rule.priority = static_cast<int>(r.at("priority").as_int(1000));
    rule.when = When::from_json(r.at("when"));
    if (!rule.match.empty()) c.rules.push_back(rule);
  }

  const Json& h = j.at("hooks");
  c.hooks.mode = h.at("mode").as_string("auto");
  c.hooks.patterns = resolve(c.base_dir, h.at("patterns").as_string());
  c.hooks.allow_fallback = h.at("allowFallback").as_bool(true);

  const Json& lg = j.at("log");
  c.log.file = resolve(c.base_dir, lg.at("file").as_string());
  c.log.verbose = lg.at("verbose").as_bool(false);
  (void)diag;
  return c;
}

Json Config::to_json() const {
  Json j = Json::make_object();
  j.set("version", Json::make_number(version));
  Json cl = Json::make_object();
  cl.set("exe", Json::make_string(client.exe));
  cl.set("gameDir", Json::make_string(client.game_dir));
  cl.set("portal", Json::make_string(client.portal));
  cl.set("realmlist", Json::make_string(client.realmlist));
  Json args = Json::make_array(); for (const auto& a : client.args) args.push(Json::make_string(a));
  cl.set("args", args);
  cl.set("clearCache", Json::make_bool(client.clear_cache));
  j.set("client", cl);

  Json mods = Json::make_array();
  for (const auto& m : this->mods) {
    Json o = Json::make_object();
    o.set("name", Json::make_string(m.name));
    o.set("path", Json::make_string(m.path));
    o.set("root", Json::make_string(m.root));
    o.set("manifest", Json::make_string(m.manifest));
    o.set("enabled", Json::make_bool(m.enabled));
    o.set("priority", Json::make_number(m.priority));
    o.set("when", m.when.to_json());
    mods.push(o);
  }
  j.set("mods", mods);

  Json maps = Json::make_array(); for (const auto& m : mappings) maps.push(Json::make_string(m));
  j.set("mappings", maps);
  Json rules = Json::make_array();
  for (const auto& r : this->rules) {
    Json o = Json::make_object();
    o.set("match", Json::make_string(r.match));
    o.set("replace", Json::make_string(r.replace));
    o.set("priority", Json::make_number(r.priority));
    o.set("when", r.when.to_json());
    rules.push(o);
  }
  j.set("rules", rules);
  Json h = Json::make_object();
  h.set("mode", Json::make_string(hooks.mode));
  h.set("patterns", Json::make_string(hooks.patterns));
  h.set("allowFallback", Json::make_bool(hooks.allow_fallback));
  j.set("hooks", h);
  Json lg = Json::make_object();
  lg.set("file", Json::make_string(log.file));
  lg.set("verbose", Json::make_bool(log.verbose));
  j.set("log", lg);
  return j;
}

bool load_config(const std::string& path, Config* out, Diagnostics* diag) {
  std::string text, err;
  if (!read_text_file(path, &text, &err)) {
    if (diag) diag->error(path, err);
    return false;
  }
  std::string perr;
  Json j = Json::parse(text, &perr);
  if (!perr.empty()) {
    if (diag) diag->error(path, perr);
    return false;
  }
  if (j.type != Json::Type::Object) {
    if (diag) diag->error(path, "配置根节点必须是对象");
    return false;
  }
  *out = Config::from_json(j, path, diag);
  if (diag) diag->info(path, "配置已载入: " + std::to_string(out->mods.size()) + " 个模组包, " + std::to_string(out->mappings.size()) + " 个映射文件");
  return true;
}

std::string default_config_text(const std::string& game_dir) {
  Config c;
  c.client.game_dir = game_dir;
  return "// wowmod-loadexe 配置示例（支持 // 注释与尾随逗号）\n" + c.to_json().dump(2) + "\n";
}

bool validate_config(const Config& cfg, Diagnostics* diag) {
  auto d = [&](Level l, const std::string& where, const std::string& msg) {
    if (!diag) return;
    if (l == Level::Error) diag->error(where, msg);
    else if (l == Level::Warn) diag->warn(where, msg);
    else diag->info(where, msg);
  };
  bool ok = true;
  if (!cfg.client.exe.empty() && !file_exists(cfg.client.exe)) {
    d(Level::Error, "client.exe", "文件不存在: " + cfg.client.exe); ok = false;
  }
  if (!cfg.client.game_dir.empty() && !dir_exists(cfg.client.game_dir)) {
    d(Level::Error, "client.gameDir", "目录不存在: " + cfg.client.game_dir); ok = false;
  }
  if (cfg.client.exe.empty() && cfg.client.game_dir.empty()) {
    d(Level::Warn, "client", "未指定 exe / gameDir；将使用启动器所在目录自动发现客户端");
  }
  std::vector<std::string> names;
  for (const auto& m : cfg.mods) {
    if (!m.enabled) { d(Level::Info, "mods", "已禁用: " + m.name); continue; }
    if (m.path.empty() || !dir_exists(m.path)) {
      d(Level::Error, "mods", "模组目录不存在: " + m.name + " -> " + m.path); ok = false;
    }
    if (!m.root.empty() && !dir_exists(join_path(m.path, m.root))) {
      d(Level::Warn, "mods", "模组 root 子目录不存在: " + m.name + "/" + m.root);
    }
    if (!m.manifest.empty() && !file_exists(m.manifest)) {
      d(Level::Error, "mods", "manifest 不存在: " + m.manifest); ok = false;
    }
    if (std::find(names.begin(), names.end(), m.name) != names.end()) d(Level::Warn, "mods", "重复的模组名: " + m.name);
    names.push_back(m.name);
  }
  if (cfg.mods.empty()) d(Level::Info, "mods", "没有启用任何模组包；仍可用于 portal / 配置覆盖");
  for (const auto& p : cfg.mappings) {
    if (!file_exists(p)) { d(Level::Error, "mappings", "映射文件不存在: " + p); ok = false; }
  }
  if (!cfg.hooks.patterns.empty() && !file_exists(cfg.hooks.patterns)) {
    d(Level::Warn, "hooks.patterns", "特征文件不存在: " + cfg.hooks.patterns + "（将退化为纯 VFS 模式）");
  }
  std::string mode = to_lower(cfg.hooks.mode);
  if (mode != "auto" && mode != "vfs" && mode != "fileid" && mode != "off") {
    d(Level::Error, "hooks.mode", "只能是 auto / vfs / fileid / off"); ok = false;
  }
  for (const auto& r : cfg.rules) {
    if (!r.replace.empty() && !file_exists(r.replace)) {
      d(Level::Warn, "rules", "规则目标文件不存在: " + r.replace);
    }
  }
  // 注意：这里永远不检查"客户端版本是否受支持"。
  return ok;
}

}  // namespace wowmod
