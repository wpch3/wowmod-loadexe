// SPDX-License-Identifier: MIT
#include "wowmod/hooks.hpp"

#include <algorithm>
#include <sstream>

namespace wowmod {

namespace {

// 分词：空格分隔，但保留引号内容（用于 str:"a b c"）
std::vector<std::string> tokenize(const std::string& s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    if (i >= s.size()) break;
    std::string tok;
    bool quote = false;
    while (i < s.size()) {
      char c = s[i];
      if (!quote && std::isspace(static_cast<unsigned char>(c))) break;
      if (c == '"') { quote = !quote; ++i; continue; }
      if (!quote && (c == ',' || c == '|')) { ++i; continue; }
      tok.push_back(c);
      ++i;
    }
    if (!tok.empty()) out.push_back(tok);
  }
  return out;
}

bool hex_byte(const std::string& t, int* out) {
  std::string s = t;
  if (starts_with(s, "0x") || starts_with(s, "0X")) s = s.substr(2);
  if (!s.empty() && (s.back() == 'h' || s.back() == 'H')) s.pop_back();
  if (s.size() != 2) return false;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  int a = nibble(s[0]), b = nibble(s[1]);
  if (a < 0 || b < 0) return false;
  *out = (a << 4) | b;
  return true;
}

std::string unescape(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      char c = s[++i];
      switch (c) {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '0': out.push_back('\0'); break;
        default: out.push_back(c); break;
      }
    } else out.push_back(s[i]);
  }
  return out;
}

}  // namespace

Pattern Pattern::parse(const std::string& text, std::string* err) {
  Pattern p;
  p.source = text;
  if (err) err->clear();
  // 支持无空格的连续 hex 串 "488B05????????"
  std::string compact = replace_all(text, " ", "");
  bool pure_hex_or_wild = !compact.empty() && compact.find_first_not_of("0123456789abcdefABCDEF?xX") == std::string::npos;
  if (pure_hex_or_wild && compact.size() % 2 == 0 && !starts_with(to_lower(text), "str:")) {
    for (size_t i = 0; i + 1 < compact.size(); i += 2) {
      std::string t = compact.substr(i, 2);
      if (t == "??" || t == "?x" || t == "?X") p.bytes.push_back(-1);
      else {
        int b = 0;
        if (!hex_byte(t, &b)) { if (err) *err = "无效字节: " + t; return Pattern{}; }
        p.bytes.push_back(b);
      }
    }
    return p;
  }
  for (const auto& tok : tokenize(text)) {
    if (tok == "?" || tok == "??" || tok == "*") { p.bytes.push_back(-1); continue; }
    if (starts_with(tok, "str:")) {
      std::string s = unescape(tok.substr(4));
      for (unsigned char c : s) p.bytes.push_back(static_cast<int>(c));
      continue;
    }
    int b = 0;
    if (hex_byte(tok, &b)) { p.bytes.push_back(b); continue; }
    if (starts_with(tok, "\"")) {
      for (unsigned char c : unescape(tok)) p.bytes.push_back(static_cast<int>(c));
      continue;
    }
    if (err) *err = "无法解析的特征 token: " + tok;
    return Pattern{};
  }
  return p;
}

std::optional<size_t> Pattern::find(const std::vector<uint8_t>& h, size_t start) const {
  if (!valid() || h.size() < bytes.size()) return std::nullopt;
  for (size_t i = start; i + bytes.size() <= h.size(); ++i) {
    bool ok = true;
    for (size_t k = 0; k < bytes.size(); ++k) {
      if (bytes[k] >= 0 && h[i + k] != static_cast<uint8_t>(bytes[k])) { ok = false; break; }
    }
    if (ok) return i;
  }
  return std::nullopt;
}

std::vector<size_t> Pattern::find_all(const std::vector<uint8_t>& h, size_t start) const {
  std::vector<size_t> out;
  size_t pos = start;
  while (true) {
    auto f = find(h, pos);
    if (!f) break;
    out.push_back(*f);
    pos = *f + 1;
  }
  return out;
}

HookDescriptor hook_from_json(const Json& j, Diagnostics* diag) {
  HookDescriptor d;
  d.name = j.at("name").as_string();
  d.kind = j.at("kind").as_string("fileId");
  d.arch = j.at("arch").as_string();
  d.module = j.at("module").as_string();
  d.result = j.at("result").as_string("rax=pathPtr");
  d.id_register = j.at("idRegister").as_string("rdx");
  d.path_register = j.at("pathRegister").as_string();
  d.offset = static_cast<int>(j.at("offset").as_int(0));
  d.priority = static_cast<int>(j.at("priority").as_int(0));
  d.allow_multiple = j.at("allowMultiple").as_bool(false);
  d.note = j.at("note").as_string();
  d.when = When::from_json(j.at("when"));
  for (const auto& v : j.at("storage").as_array()) d.storage.push_back(v.as_string());
  std::string perr;
  d.pattern = Pattern::parse(j.at("pattern").as_string(), &perr);
  if (!perr.empty() && diag) diag->error("patterns", d.name + ": " + perr);
  if (d.pattern.bytes.empty() && diag) diag->warn("patterns", d.name + ": 空的 pattern，将被忽略");
  return d;
}

std::vector<HookDescriptor> load_hook_patterns(const std::string& path, Diagnostics* diag) {
  std::vector<HookDescriptor> out;
  std::string text, err;
  if (!read_text_file(path, &text, &err)) {
    if (diag) diag->warn(path, err + "（使用纯 VFS 模式）");
    return out;
  }
  std::string perr;
  Json j = Json::parse(text, &perr);
  if (!perr.empty()) {
    if (diag) diag->warn(path, perr + "（使用纯 VFS 模式）");
    return out;
  }
  const Json& list = j.type == Json::Type::Array ? j : j.at("patterns");
  for (const auto& item : list.as_array()) {
    HookDescriptor d = hook_from_json(item, diag);
    if (d.pattern.valid()) out.push_back(std::move(d));
  }
  if (diag) diag->info(path, "载入 " + std::to_string(out.size()) + " 条 hook 特征（数据驱动，无内置版本表）");
  return out;
}

Json HookMatch::to_json() const {
  Json j = Json::make_object();
  j.set("name", Json::make_string(descriptor.name));
  j.set("kind", Json::make_string(descriptor.kind));
  j.set("offset", Json::make_number(static_cast<double>(file_offset)));
  j.set("rva", Json::make_number(static_cast<double>(rva)));
  j.set("matches", Json::make_number(static_cast<double>(match_count)));
  j.set("reason", Json::make_string(reason));
  j.set("arch", Json::make_string(descriptor.arch));
  j.set("idRegister", Json::make_string(descriptor.id_register));
  j.set("module", Json::make_string(module));
  return j;
}

Json HookPlan::to_json() const {
  Json j = Json::make_object();
  j.set("mode", Json::make_string(mode));
  j.set("reason", Json::make_string(reason));
  Json arr = Json::make_array();
  for (const auto& m : matches) arr.push(m.to_json());
  j.set("matches", arr);
  return j;
}

std::vector<HookImage> collect_hook_images(const Config& cfg, const ClientInfo& ci,
                                           const std::vector<uint8_t>& exe_bytes, Diagnostics* diag) {
  std::vector<HookImage> images;
  if (!exe_bytes.empty()) images.push_back({"", exe_bytes});
  std::vector<std::string> names = cfg.hooks.scan_targets;
  for (const auto& d : ci.companion_dlls) {
    if (std::find(names.begin(), names.end(), d) == names.end()) names.push_back(d);
  }
  // exe 尚未落盘（跨机预览配置）时 detect 会把 game_dir 设成 exe 路径本身，这里兜一层。
  std::string dir = ci.game_dir;
  if (iequals(file_extension(dir), ".exe") || iequals(file_extension(dir), ".dll")) dir = parent_path(dir);
  for (const auto& n : names) {
    if (n.empty()) continue;
    std::string p = file_exists(n) ? n : join_path(dir, n);
    std::vector<uint8_t> bytes;
    std::string rerr;
    if (!read_binary_file(p, &bytes, &rerr)) {
      if (diag) diag->info("hooks", "附加扫描模块未找到: " + n + "（" + rerr + "）");
      continue;
    }
    if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') continue;
    images.push_back({file_name(p), std::move(bytes)});
    if (diag) diag->info("hooks", "附加扫描模块: " + file_name(p) + " (" + std::to_string(images.back().bytes.size()) + " 字节)");
  }
  return images;
}

HookPlan plan_hooks(const Config& cfg, const ClientInfo& ci, const std::vector<HookImage>& images, Diagnostics* diag) {
  HookPlan plan;
  std::string mode = to_lower(cfg.hooks.mode);
  if (mode == "off") { plan.mode = "off"; plan.reason = "配置里 hooks.mode=off"; return plan; }
  if (mode == "vfs") { plan.reason = "配置里 hooks.mode=vfs（仅使用通用 VFS 覆盖）"; return plan; }

  std::vector<HookDescriptor> ds;
  std::vector<std::string> files = cfg.hooks.pattern_files;
  if (files.empty() && !cfg.hooks.patterns.empty()) files.push_back(cfg.hooks.patterns);  // 兼容旧单字段
  for (const auto& pf : files) {
    auto part = load_hook_patterns(pf, diag);
    ds.insert(ds.end(), part.begin(), part.end());
  }
  if (files.empty() && diag)
    diag->info("hooks", "没有配置任何特征文件（纯 VFS 模式，任何版本可用）");
  if (ds.empty()) {
    plan.reason = "没有可用的 hook 特征，自动退化为纯 VFS 覆盖（不修改客户端代码，任何版本可用）";
    if (diag) diag->info("hooks", plan.reason);
    return plan;
  }

  for (const auto& img : images) {
    PeImage pe;
    std::string peerr;
    bool have_image = pe.load(img.bytes, &peerr, img.mapped);
    for (const auto& d : ds) {
      if (!d.arch.empty() && !iequals(d.arch, ci.arch)) continue;
      if (!d.module.empty() && !iequals(d.module, img.module) &&
          !iequals(d.module, file_name(img.module))) continue;
      if (!d.when.matches(ci)) continue;
      if (!d.storage.empty() && std::none_of(d.storage.begin(), d.storage.end(), [&](const std::string& s) { return iequals(s, ci.storage); })) continue;
      auto all = d.pattern.find_all(img.bytes);
      if (all.empty()) {
        if (diag) diag->info("hooks", "特征 [" + d.name + "] 未匹配 " + (img.module.empty() ? "主 exe" : img.module));
        continue;
      }
      if (all.size() > 1 && !d.allow_multiple) {
        if (diag) diag->warn("hooks", "特征 [" + d.name + "] 在 " + (img.module.empty() ? "主 exe" : img.module) +
                                 " 匹配 " + std::to_string(all.size()) + " 处，不唯一，跳过（避免误 hook）");
        continue;
      }
      size_t off = all.front() + static_cast<size_t>(d.offset >= 0 ? d.offset : 0);
      if (off >= img.bytes.size()) continue;
      HookMatch m;
      m.descriptor = d;
      m.module = img.module;
      m.file_offset = off;
      m.match_count = all.size();
      m.reason = "唯一匹配" + std::string(all.size() > 1 ? "（取第一处）" : "") +
                 (img.module.empty() ? "" : " @ " + img.module);
      if (have_image) {
        auto rva = pe.offset_to_rva(static_cast<uint32_t>(off));
        if (rva) m.rva = *rva;
      }
      plan.matches.push_back(std::move(m));
    }
  }
  if (plan.matches.empty()) {
    plan.reason = "没有任何特征能唯一匹配这个客户端；" +
                  std::string(cfg.hooks.allow_fallback ? "已退化为纯 VFS 模式，客户端照常启动" : "按配置拒绝启动");
    if (diag) diag->warn("hooks", plan.reason);
    return plan;
  }
  std::sort(plan.matches.begin(), plan.matches.end(), [](const HookMatch& a, const HookMatch& b) {
    if (a.descriptor.priority != b.descriptor.priority) return a.descriptor.priority > b.descriptor.priority;
    return a.descriptor.pattern.size() > b.descriptor.pattern.size();
  });
  plan.mode = "fileid";
  plan.reason = "通过实际二进制能力探测选中 hook 点: " + plan.matches.front().descriptor.name;
  if (diag) diag->info("hooks", plan.reason);
  return plan;
}

HookPlan plan_hooks(const Config& cfg, const ClientInfo& ci, const std::vector<uint8_t>& exe_bytes, Diagnostics* diag) {
  return plan_hooks(cfg, ci, collect_hook_images(cfg, ci, exe_bytes, diag), diag);
}

Json scan_report(const std::vector<HookImage>& images, const std::vector<HookDescriptor>& ds, Diagnostics* diag) {
  Json j = Json::make_object();
  j.set("modules", Json::make_number(static_cast<double>(images.size())));
  Json mods = Json::make_array();
  Json results = Json::make_array();
  // 直接对内存做扫描，不需要临时文件。
  for (const auto& img : images) {
    std::string label = img.module.empty() ? "主 exe" : img.module;
    mods.push(Json::make_string(label));
    PeImage pe;
    std::string peerr;
    bool have_pe = pe.load(img.bytes, &peerr, img.mapped);
    for (const auto& d : ds) {
      if (!d.module.empty() && !iequals(d.module, img.module)) continue;
      auto all = d.pattern.find_all(img.bytes);
      Json o = Json::make_object();
      o.set("name", Json::make_string(d.name));
      o.set("module", Json::make_string(label));
      o.set("matches", Json::make_number(static_cast<double>(all.size())));
      Json offs = Json::make_array();
      for (size_t off : all) {
        Json x = Json::make_object();
        x.set("fileOffset", Json::make_number(static_cast<double>(off)));
        if (have_pe) {
          auto rva = pe.offset_to_rva(static_cast<uint32_t>(off));
          if (rva) x.set("rva", Json::make_number(static_cast<double>(*rva)));
        }
        offs.push(x);
        if (offs.as_array().size() >= 16) break;
      }
      o.set("offsets", offs);
      results.push(o);
    }
  }
  j.set("moduleNames", mods);
  j.set("results", results);
  if (diag) diag->info("scan", "扫描 " + std::to_string(images.size()) + " 个模块 / " + std::to_string(ds.size()) + " 条特征");
  return j;
}

Json scan_report(const std::string& exe_path, const std::vector<HookDescriptor>& ds, Diagnostics* diag,
                 bool mapped) {
  Json j = Json::make_object();
  j.set("exe", Json::make_string(exe_path));
  std::vector<uint8_t> bytes;
  std::string err;
  if (!read_binary_file(exe_path, &bytes, &err)) {
    j.set("error", Json::make_string(err));
    return j;
  }
  PeImage pe;
  std::string peerr;
  bool have_pe = pe.load(bytes, &peerr, mapped);
  j.set("pe", Json::make_bool(have_pe));
  j.set("size", Json::make_number(static_cast<double>(bytes.size())));
  if (have_pe) {
    j.set("arch", Json::make_string(pe.machine == 0x8664 ? "x64" : pe.machine == 0xAA64 ? "arm64" : pe.machine == 0x14C ? "x86" : "unknown"));
    Json secs = Json::make_array();
    for (const auto& s : pe.sections) {
      Json o = Json::make_object();
      o.set("name", Json::make_string(s.name));
      o.set("rva", Json::make_number(s.rva));
      o.set("rawPtr", Json::make_number(s.raw_ptr));
      o.set("rawSize", Json::make_number(s.raw_size));
      o.set("executable", Json::make_bool(s.executable));
      secs.push(o);
    }
    j.set("sections", secs);
  }
  Json results = Json::make_array();
  for (const auto& d : ds) {
    auto all = d.pattern.find_all(bytes);
    Json o = Json::make_object();
    o.set("name", Json::make_string(d.name));
    o.set("patternLength", Json::make_number(static_cast<double>(d.pattern.size())));
    o.set("matches", Json::make_number(static_cast<double>(all.size())));
    Json offs = Json::make_array();
    for (size_t off : all) {
      Json x = Json::make_object();
      x.set("fileOffset", Json::make_number(static_cast<double>(off)));
      if (have_pe) {
        auto rva = pe.offset_to_rva(static_cast<uint32_t>(off));
        if (rva) x.set("rva", Json::make_number(static_cast<double>(*rva)));
      }
      offs.push(x);
      if (offs.as_array().size() >= 16) break;
    }
    o.set("offsets", offs);
    results.push(o);
  }
  j.set("results", results);
  if (diag) diag->info("scan", "扫描 " + std::to_string(ds.size()) + " 条特征 / " + std::to_string(bytes.size()) + " 字节");
  return j;
}

}  // namespace wowmod
