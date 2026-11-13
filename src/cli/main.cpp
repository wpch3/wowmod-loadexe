// wowmod CLI: detect / validate / plan / scan / launch / init
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "wowmod/config.hpp"
#include "wowmod/discover.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/json.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/util.hpp"
#include "wowmod/vfs.hpp"
#include "wowmod/version.hpp"
#include "platform/launch.hpp"

namespace fs = std::filesystem;
using namespace wowmod;

namespace {

const char* kBanner =
    "  __      __             _              _   _           _              \n"
    "  \\ \\    / /___  _ __ __| | ___  _ __  | | | | ___   __| | ___ _ __ ___ \n"
    "   \\ \\/\\/ / _ \\| '__/ _` |/ _ \\| '_ \\ | |_| |/ _ \\ / _` |/ _ \\ '__/ _ \\\n"
    "    \\  /\\  / (_) | | | (_| | (_) | | | |  _  |  __/| (_| |  __/ | |  __/\n"
    "     \\/  \\/ \\___/|_|  \\__,_|\\___/|_| |_|_| |_|\\___| \\__,_|\\___|_|  \\___|\n"
    "  通用版本 WoW 模组加载器  ·  no version whitelist, no hardcoded offsets\n";

struct Args {
  std::string command;
  std::map<std::string, std::string> opts;
  bool json = false, help = false;
  std::string opt(const std::string& k, const std::string& def = "") const {
    auto it = opts.find(k);
    return it == opts.end() ? def : it->second;
  }
  bool has(const std::string& k) const { return opts.count(k) != 0; }
};

Args parse_args(int argc, char** argv) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    std::string s = argv[i];
    if (starts_with(s, "--")) {
      std::string body = s.substr(2);
      size_t eq = body.find('=');
      std::string key = eq == std::string::npos ? body : body.substr(0, eq);
      std::string val = eq == std::string::npos ? "" : body.substr(eq + 1);
      if (key == "json") { a.json = true; continue; }
      if (key == "help" || key == "h") { a.help = true; continue; }
      if (key == "force" || key == "verbose" || key == "dry-run" || key == "color") { a.opts[key] = "1"; continue; }
      if (val.empty() && i + 1 < argc && !starts_with(std::string(argv[i + 1]), "--")) val = argv[++i];
      a.opts[key] = val;
    } else if (a.command.empty()) {
      a.command = s;
    } else {
      a.opts["extra" + std::to_string(i)] = s;
    }
  }
  return a;
}

std::string help_text() {
  return
      "用法: wowmod <命令> [选项]\n\n"
      "命令:\n"
      "  init       生成一份示例配置与目录结构\n"
      "  detect     探测客户端（版本/架构/存储/私服 portal），不做任何版本校验\n"
      "  validate   校验配置、模组包、映射文件\n"
      "  plan       干跑：输出完整的覆盖表与 hook 选择（不启动游戏）\n"
      "  scan       扫描客户端 exe，报告 hook 特征匹配情况（用于适配新版本）\n"
      "  adapt      把邻近版本的特征自动放宽成你的 exe 上唯一匹配的特征\n"
      "  discover   只用自己的 exe 自动找出候选 hook 点（无需上传任何文件）\n"
      "  launch     启动客户端并注入覆盖层（Windows；其他平台给出提示）\n"
      "  version    显示加载器版本\n\n"
      "选项:\n"
      "  --config FILE    配置文件（默认当前目录 wowmod.json）\n"
      "  --exe FILE       覆盖配置中的客户端 exe\n"
      "  --dir DIR        覆盖配置中的游戏目录\n"
      "  --patterns FILE  覆盖 hook 特征文件\n"
      "  --pattern TEXT   adapt 用的原始特征（IDA 风格字节串）\n"
      "  --from FILE      adapt 从某个 patterns.json 的第一条取起点特征\n"
      "  --anchors A,B,C  discover 用的自定义锚点字符串（逗号分隔）\n"
      "  --emit FILE      discover 把最佳候选写成 patterns.json\n"
      "  --out FILE       adapt 输出的特征文件（默认 hooks/patterns.adapted.json）\n"
      "  --name NAME      adapt 生成的条目名\n"
      "  --id-register R  adapt 生成的 idRegister（默认 rdx）\n"
      "  --module DLL     特征属于哪个模块（私服壳 exe 时通常是 Wow_loader.dll）\n"
      "  --mapped         --exe 指向运行时内存转储（.img），按 RVA=偏移分析加密壳客户端\n"
      "  --materialize DIR  plan 时把内存生成文件写到 DIR 便于检查\n"
      "  --json           机器可读输出\n"
      "  --force          init 时覆盖已有文件\n\n"
      "示例:\n"
      "  wowmod init --dir \"D:/Games/MyPrivateServer\"\n"
      "  wowmod detect --dir \"D:/Games/MyPrivateServer\"\n"
      "  wowmod plan --json > plan.json\n"
      "  wowmod adapt --exe Wow.exe --pattern \"48 89 5C 24 08 57 ...\"\n"
      "  wowmod launch --config wowmod.json\n";
}

struct Session {
  Config cfg;
  ClientInfo ci;
  MappingTable mappings;
  Vfs vfs;
  Diagnostics diag;
  HookPlan hooks;
  std::string config_path;
  bool config_loaded = false;
};

std::string find_config(const Args& a) {
  if (a.has("config")) return absolute_path(a.opt("config"));
  std::string cwd = absolute_path(".");
  std::string local = join_path(cwd, "wowmod.json");
  if (file_exists(local)) return local;
  std::string near_exe = join_path(exe_dir_path(), "wowmod.json");
  if (file_exists(near_exe)) return near_exe;
  return local;
}

bool prepare(const Args& a, Session* s) {
  s->config_path = find_config(a);
  s->config_loaded = file_exists(s->config_path);
  if (s->config_loaded) {
    if (!load_config(s->config_path, &s->cfg, &s->diag)) return false;
  } else {
    s->cfg.base_dir = absolute_path(".");
    s->cfg.path = s->config_path;
    s->diag.info("config", "未找到配置文件 " + s->config_path + "，使用默认空配置（可运行 wowmod init 生成）");
  }
  if (a.has("exe")) s->cfg.client.exe = absolute_path(a.opt("exe"));
  if (a.has("dir")) {
    s->cfg.client.game_dir = absolute_path(a.opt("dir"));
    // 命令行 --dir 明确指定了要探测的客户端目录，覆盖配置里的 exe
    if (!a.has("exe")) s->cfg.client.exe.clear();
  }
  if (a.has("patterns")) {
    s->cfg.hooks.pattern_files = {absolute_path(a.opt("patterns"))};
    s->cfg.hooks.patterns = s->cfg.hooks.pattern_files.front();
  }

  std::string target;
  if (!s->cfg.client.exe.empty()) target = s->cfg.client.exe;
  else if (!s->cfg.client.game_dir.empty()) target = s->cfg.client.game_dir;
  else target = absolute_path(".");
  std::vector<uint8_t> exe_bytes;
  s->ci = detect_client(target, &s->diag, &exe_bytes);
  apply_display_overrides(&s->ci, s->cfg.client.version, s->cfg.client.build);
  if (s->cfg.client.exe.empty() && !s->ci.exe_path.empty()) s->cfg.client.exe = s->ci.exe_path;
  if (s->cfg.client.game_dir.empty() && !s->ci.game_dir.empty()) s->cfg.client.game_dir = s->ci.game_dir;

  for (const auto& p : s->cfg.mappings) s->mappings.load_file(p, &s->diag);
  s->vfs.build(s->cfg, s->ci, s->mappings, &s->diag);
  if (a.has("materialize")) s->vfs.materialize_generated(absolute_path(a.opt("materialize")), &s->diag);

  // detect 已把 exe 字节放进 exe_bytes，特征扫描直接复用，不再重复读大文件
  s->hooks = plan_hooks(s->cfg, s->ci, exe_bytes, &s->diag);
  return true;
}

Json session_json(const Session& s) {
  Json j = Json::make_object();
  j.set("config", Json::make_string(s.config_path));
  j.set("configLoaded", Json::make_bool(s.config_loaded));
  j.set("client", s.ci.to_json());
  j.set("hooks", s.hooks.to_json());
  j.set("plan", s.vfs.plan_json());
  Json d = Json::make_array();
  for (const auto& it : s.diag.items()) {
    Json o = Json::make_object();
    o.set("level", Json::make_string(it.level == Level::Error ? "error" : it.level == Level::Warn ? "warn" : "info"));
    o.set("where", Json::make_string(it.where));
    o.set("message", Json::make_string(it.message));
    d.push(o);
  }
  j.set("diagnostics", d);
  return j;
}

int cmd_detect(const Args& a, Session& s) {
  if (a.json) {
    std::cout << session_json(s).dump(2) << "\n";
    return 0;
  }
  std::cout << kBanner << "\n" << s.ci.display() << "\n\n";
  std::cout << "说明:\n";
  for (const auto& n : s.ci.notes) std::cout << "  - " << n << "\n";
  if (!s.diag.items().empty()) std::cout << "\n" << s.diag.render(a.has("color"));
  return 0;
}

int cmd_validate(const Args& a, Session& s) {
  Diagnostics d = s.diag;
  bool ok = validate_config(s.cfg, &d);
  if (a.json) {
    Json j = Json::make_object();
    j.set("ok", Json::make_bool(ok));
    Json arr = Json::make_array();
    for (const auto& it : d.items()) {
      Json o = Json::make_object();
      o.set("level", Json::make_string(it.level == Level::Error ? "error" : it.level == Level::Warn ? "warn" : "info"));
      o.set("where", Json::make_string(it.where));
      o.set("message", Json::make_string(it.message));
      arr.push(o);
    }
    j.set("diagnostics", arr);
    std::cout << j.dump(2) << "\n";
  } else {
    std::cout << d.render(a.has("color"));
    std::cout << (ok ? "\n校验通过。\n" : "\n校验失败，请修正上面的错误。\n");
  }
  return ok ? 0 : 1;
}

int cmd_plan(const Args& a, Session& s) {
  if (a.json) {
    std::cout << session_json(s).dump(2) << "\n";
    return 0;
  }
  std::cout << kBanner << "\n";
  std::cout << "配置: " << s.config_path << (s.config_loaded ? "" : " (未找到，使用默认)") << "\n";
  std::cout << "客户端: " << s.ci.version_string << " | " << s.ci.arch << " | " << s.ci.storage << "\n";
  std::cout << "hook 模式: " << s.hooks.mode << " — " << s.hooks.reason << "\n";
  std::cout << "统计: " << s.vfs.stats().packs << " 个模组包, " << s.vfs.stats().pack_files
            << " 个文件, " << s.vfs.stats().overlays << " 条覆盖, "
            << s.vfs.stats().id_mappings << " 个 ID 映射, "
            << s.vfs.stats().generated << " 个内存文件\n\n";
  std::cout << s.vfs.plan_text() << "\n";
  if (!s.cfg.rules.empty()) {
    std::cout << "规则 (" << s.cfg.rules.size() << "):\n";
    for (const auto& r : s.cfg.rules) std::cout << "  " << r.match << " -> " << (r.replace.empty() ? "(屏蔽)" : r.replace) << "\n";
    std::cout << "\n";
  }
  if (!s.diag.items().empty()) std::cout << s.diag.render(a.has("color"));
  return 0;
}

int cmd_scan(const Args& a, Session& s) {
  std::string exe = a.has("exe") ? absolute_path(a.opt("exe")) : s.cfg.client.exe;
  if (exe.empty() || !file_exists(exe)) {
    std::cerr << "请用 --exe 指定一个有效的客户端 exe\n";
    return 1;
  }
  std::vector<HookDescriptor> ds;
  for (const auto& pf : s.cfg.hooks.pattern_files) {
    auto part = load_hook_patterns(pf, &s.diag);
    ds.insert(ds.end(), part.begin(), part.end());
  }
  std::vector<uint8_t> main_bytes;
  std::string rerr;
  read_binary_file(exe, &main_bytes, &rerr);
  bool mapped = a.has("mapped");
  std::vector<HookImage> images;
  if (mapped) images.push_back({"", main_bytes, true});
  else images = collect_hook_images(s.cfg, s.ci, main_bytes, &s.diag);
  Json report = images.size() > 1 || mapped ? scan_report(images, ds, &s.diag) : scan_report(exe, ds, &s.diag);
  if (a.json) {
    std::cout << report.dump(2) << "\n";
    return 0;
  }
  std::cout << "扫描: " << exe << " (" << report.at("size").as_int(0) << " 字节, PE=" << (report.at("pe").as_bool() ? "是" : "否") << ")\n";
  const auto& results = report.at("results").as_array();
  if (results.empty()) std::cout << "没有载入任何特征文件。用 --patterns FILE 指定，或在配置里设置 hooks.patterns。\n";
  for (const auto& r : results) {
    long long n = r.at("matches").as_int(0);
    std::cout << "  " << (n == 1 ? "[唯一]  " : n == 0 ? "[无匹配]" : "[多匹配]") << " "
              << r.at("name").as_string();
    if (r.has("module")) std::cout << " [" << r.at("module").as_string() << "]";
    std::cout << " -> " << n << " 处";
    for (const auto& off : r.at("offsets").as_array()) {
      std::cout << " 0x" << to_hex(static_cast<uint64_t>(off.at("fileOffset").as_int(0)));
      if (off.has("rva")) std::cout << "(rva 0x" << to_hex(static_cast<uint64_t>(off.at("rva").as_int(0))) << ")";
    }
    std::cout << "\n";
  }
  std::cout << "\n提示: 特征来自外部 JSON，适配新客户端只需添加一条数据，无需改代码。\n";
  return 0;
}

int cmd_adapt(const Args& a, Session& s) {
  std::string exe = a.has("exe") ? absolute_path(a.opt("exe")) : s.cfg.client.exe;
  if (exe.empty() || !file_exists(exe)) {
    std::cerr << "请用 --exe 指定你的 12.0.7 客户端 exe（或在配置里设置 client.exe）\n";
    return 1;
  }
  std::string pattern = trim(a.opt("pattern"));
  std::string source_note;
  if (pattern.empty() && a.has("from")) {
    std::string from = absolute_path(a.opt("from"));
    auto ds = load_hook_patterns(from, &s.diag);
    if (!ds.empty()) { pattern = ds.front().pattern.source; source_note = "取自 " + from + " [" + ds.front().name + "]"; }
  }
  if (pattern.empty()) {
    // 没给特征时，用配置里已登记的第一条作为起点
    for (const auto& pf : s.cfg.hooks.pattern_files) {
      auto ds = load_hook_patterns(pf, &s.diag);
      if (!ds.empty()) { pattern = ds.front().pattern.source; source_note = "取自 " + pf + " [" + ds.front().name + "]"; break; }
    }
  }
  if (pattern.empty()) {
    std::cerr << "没有可用作起点的特征。请提供 --pattern \"48 89 5C 24 ...\" 或 --from FILE\n"
              << "（可从邻近 12.x build 的公开 pattern 开始，工具会自动放宽成你这个 exe 上唯一匹配的版本）\n";
    return 1;
  }

  std::string base = s.config_loaded ? parent_path(s.config_path) : absolute_path(".");
  std::string out = a.has("out") ? absolute_path(a.opt("out")) : join_path(base, "hooks/patterns.adapted.json");
  std::string name = a.opt("name");
  if (name.empty()) name = "adapted-" + file_stem(exe);
  std::string err;
  AdaptFileResult r = adapt_pattern_file(exe, pattern, out, name, a.opt("id-register", "rdx"), &err, a.opt("module", ""));

  if (a.json) {
    Json j = r.to_json();
    j.set("exe", Json::make_string(exe));
    j.set("sourceNote", Json::make_string(source_note));
    std::cout << j.dump(2) << "\n";
    return r.ok ? 0 : 1;
  }
  std::cout << "客户端: " << exe << "  (" << s.ci.version_string << " / " << s.ci.arch << ")\n";
  std::cout << "起点特征: " << (source_note.empty() ? "命令行 --pattern" : source_note) << "\n";
  std::cout << "原始特征: " << pattern << "\n\n";
  if (!r.ok) {
    std::cout << "自适应失败: " << r.reason << "\n";
    return 1;
  }
  const auto& ad = r.adapted;
  std::cout << "结果: " << ad.pattern << "\n"
            << "  固定字节 " << ad.fixed_bytes << " / 通配 " << ad.wildcard_bytes
            << " | 唯一匹配 @ 0x" << to_hex(ad.file_offset, 8) << " (rva 0x" << to_hex(ad.rva, 8) << ")"
            << " | 可执行节区: " << (ad.executable ? "是" : "否") << "\n"
            << "  " << ad.reason << "\n\n"
            << "已写入: " << r.out_path << "\n"
            << "下一步:\n"
            << "  1) 把 \"hooks.patterns\" 指向该文件（或把它加进 patterns 数组）\n"
            << "  2) wowmod scan --exe \"" << exe << "\" --patterns \"" << r.out_path << "\"\n"
            << "  3) wowmod plan --config \"" << s.config_path << "\"\n";
  if (ad.warning) std::cout << "\n⚠ 原始特征在这个 exe 上 0 处匹配：唯一命中也可能不是目标函数，请用调试器确认返回值是路径指针。\n";
  else std::cout << "\n提示：唯一匹配 ≠ 函数语义正确。首次进游戏请用 wowmod.log / 调试器确认命中点就是「按 FileDataID 打开」的入口。\n";
  return 0;
}

int cmd_discover(const Args& a, Session& s) {
  std::string exe = a.has("exe") ? absolute_path(a.opt("exe")) : s.cfg.client.exe;
  if (exe.empty() || !file_exists(exe)) {
    std::cerr << "请用 --exe 指定客户端 exe（这条命令只读取你本机的文件，不会上传任何东西）\n";
    return 1;
  }
  std::vector<uint8_t> bytes;
  std::string rerr;
  if (!read_binary_file(exe, &bytes, &rerr)) { std::cerr << rerr << "\n"; return 1; }

  std::vector<std::string> anchors;
  if (a.has("anchors")) {
    for (const auto& x : split(a.opt("anchors"), ',')) {
      std::string t = trim(x);
      if (!t.empty()) anchors.push_back(t);
    }
  }
  if (anchors.empty()) anchors = default_anchors();
  bool mapped = a.has("mapped");
  DiscoveryReport rep = discover_hook_points(bytes, anchors, mapped);
  rep.exe = exe;

  std::string emitted;
  if (a.has("emit") && !rep.candidates.empty()) {
    std::string out = absolute_path(a.opt("emit"));
    std::string name = a.opt("name");
    if (name.empty()) name = "discovered-" + file_stem(exe);
    const auto& best = rep.candidates.front();
    std::string werr;
    if (write_pattern_descriptor(out, name, best.pattern, rep.arch, a.opt("id-register", "rdx"),
                                 "由 wowmod discover 自动发现的候选点；必须用调试器核实函数返回值是路径指针", &werr,
                                 a.opt("module", "")))
      emitted = out;
    else
      s.diag.error("discover", werr);
  }

  if (a.json) {
    Json j = rep.to_json();
    j.set("emitted", Json::make_string(emitted));
    j.set("mapped", Json::make_bool(mapped));
    std::cout << j.dump(2) << "\n";
    return 0;
  }
  std::cout << (mapped ? "内存映像分析: " : "本地自动发现: ") << exe
            << " (" << (rep.pe ? rep.arch : "非 PE") << ")\n";
  std::cout << "锚点命中: " << (rep.anchors_found.empty() ? "无" : join(rep.anchors_found, ", ")) << "\n";
  std::cout << "目标 " << rep.target_count << " 个 / 代码引用 " << rep.xref_count << " 处\n";
  std::cout << "候选 hook 点: " << rep.candidates.size() << " 个\n\n";
  for (size_t i = 0; i < rep.candidates.size(); ++i) {
    const auto& c = rep.candidates[i];
    std::cout << "  [" << (i + 1) << "] " << (c.unique_matches == 1 ? "唯一匹配 ✓" : std::to_string(c.unique_matches) + "+ 处")
              << " @ rva 0x" << to_hex(c.code_rva, 8) << "  锚点=" << c.anchor << "\n"
              << "      " << c.pattern << "\n"
              << "      固定字节 " << c.fixed_bytes << " — " << c.reason << "\n";
  }
  if (rep.candidates.empty()) std::cout << "  " << rep.note << "\n";
  else std::cout << "\n⚠ " << rep.note << "\n";
  if (!emitted.empty()) std::cout << "\n已写出: " << emitted << "\n下一步: wowmod scan --patterns \"" << emitted
                                  << "\" && wowmod plan --config \"" << s.config_path << "\"\n";
  else if (!rep.candidates.empty())
    std::cout << "\n想直接用最佳候选: 加 --emit hooks/patterns.discovered.json\n";
  return 0;
}

int cmd_launch(const Args& a, Session& s) {
  if (a.has("dry-run")) return cmd_plan(a, s);
  LaunchResult r = launch_game(s.cfg, s.ci, s.vfs, s.hooks, s.diag, false);
  if (a.json) {
    Json j = Json::make_object();
    j.set("code", Json::make_number(r.code));
    j.set("message", Json::make_string(r.message));
    j.set("pid", Json::make_number(static_cast<double>(r.pid)));
    j.set("plan", s.vfs.plan_json());
    std::cout << j.dump(2) << "\n";
  } else {
    std::cout << r.message << "\n";
  }
  return r.code;
}

int cmd_init(const Args& a) {
  std::string dir = a.has("dir") ? absolute_path(a.opt("dir")) : absolute_path(".");
  bool force = a.has("force");
  auto put = [&](const std::string& rel, const std::string& content) {
    std::string p = join_path(dir, rel);
    if (file_exists(p) && !force) { std::cout << "  跳过(已存在): " << rel << "\n"; return; }
    std::string err;
    if (write_text_file(p, content, &err)) std::cout << "  创建: " << rel << "\n";
    else std::cerr << "  失败: " << err << "\n";
  };
  std::cout << "初始化目录: " << dir << "\n";
  Config c;
  c.client.game_dir = ".";
  c.client.args = {"-console"};
  c.client.portal = "127.0.0.1";
  c.mods.push_back(ModPack{"示例模型替换", "", "", "", true, 10, When{}});
  // 手写一份带注释的示例配置（更直观），相对路径都基于配置文件所在目录
  std::string config =
      "// wowmod-loadexe 配置 —— 支持 // 注释和尾随逗号\n"
      "// 所有相对路径都相对本文件所在目录；不写死任何客户端版本号。\n"
      "{\n"
      "  \"version\": 1,\n"
      "  \"client\": {\n"
      "    \"exe\": \"\",                    // 留空 = 自动发现 wow*.exe\n"
      "    \"gameDir\": \".\",               // 游戏根目录\n"
      "    \"portal\": \"127.0.0.1\",        // 私服地址：内存覆盖 WTF/Config.wtf，不改磁盘\n"
      "    \"realmlist\": \"\",              // 老客户端用：内存覆盖 realmlist.wtf\n"
      "    \"args\": [\"-console\"],\n"
      "    \"clearCache\": false\n"
      "  },\n"
      "  \"mods\": [\n"
      "    {\n"
      "      \"name\": \"示例模型替换\",\n"
      "      \"path\": \"mods/example\",\n"
      "      \"root\": \"\",                 // 包内相对于游戏根目录的子目录\n"
      "      \"enabled\": true,\n"
      "      \"priority\": 10,             // 数字越大越优先\n"
      "      \"when\": {}                  // 可选过滤；留空 = 任何版本都生效\n"
      "    }\n"
      "  ],\n"
      "  \"mappings\": [\"mappings/listfile.txt\"],\n"
      "  \"rules\": [],\n"
      "  \"hooks\": {\n"
      "    \"mode\": \"auto\",              // auto | vfs | fileid | off\n"
      "    \"patterns\": \"hooks/patterns.json\",\n"
      "    \"allowFallback\": true        // 找不到 hook 点时仍以纯 VFS 启动\n"
      "  },\n"
      "  \"log\": { \"file\": \"wowmod.log\", \"verbose\": false }\n"
      "}\n";
  put("wowmod.json", config);
  put("mappings/listfile.txt",
      "# wow-listfile 格式: fileId;filePath\n"
      "# 换成你自己的私服版本对应的 listfile（https://github.com/wowdev/wow-listfile）\n"
      "123456;World/Model/Example/Dragon.m2\n"
      "123457;World/Model/Example/DragonSkin.blp\n");
  put("mods/example/wowmod.manifest.json",
      "{\n"
      "  // 可选：直接按 FileDataID 指定替换文件，不依赖路径\n"
      "  \"files\": [\n"
      "    { \"id\": 123456, \"file\": \"Dragon.m2\" },\n"
      "    { \"path\": \"World/Model/Example/DragonSkin.blp\", \"file\": \"DragonSkin.blp\" }\n"
      "  ]\n"
      "}\n");
  put("mods/example/README.md",
      "# 示例模组包\n\n"
      "把要替换的文件按游戏内路径放进这个目录，例如：\n\n"
      "```\n"
      "mods/example/World/Model/Example/Dragon.m2\n"
      "mods/example/Interface/AddOns/MyAddon/MyAddon.lua\n"
      "```\n\n"
      "也可以用 `wowmod.manifest.json` 直接按 FileDataID 指定。\n"
      "运行 `wowmod plan` 查看最终覆盖表。\n");
  put("hooks/patterns.json",
      "{\n"
      "  // 特征码是数据，不是内置版本表。为你的私服客户端加一条即可适配。\n"
      "  // 格式: IDA 风格字节串，?? 为通配符；str:\"...\" 展开为 ASCII。\n"
      "  // 只有在实际 exe 上【唯一匹配】的特征才会被启用，其余自动跳过。\n"
      "  \"patterns\": [\n"
      "    {\n"
      "      \"name\": \"example-load-by-fileid\",\n"
      "      \"kind\": \"fileId\",\n"
      "      \"arch\": \"x64\",\n"
      "      \"pattern\": \"48 89 5C 24 08 57 48 83 EC 20 48 8B ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ??\",\n"
      "      \"offset\": 0,\n"
      "      \"idRegister\": \"rdx\",\n"
      "      \"result\": \"rax=pathPtr\",\n"
      "      \"priority\": 0,\n"
      "      \"note\": \"示例占位特征；请替换成你自己客户端的 load-by-fileid 函数入口\"\n"
      "    }\n"
      "  ]\n"
      "}\n");
  put("README.txt", "运行: wowmod detect / wowmod plan / wowmod launch\n详细文档见仓库 README.md\n");
  std::cout << "\n下一步: wowmod detect --config " << join_path(dir, "wowmod.json") << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Args a = parse_args(argc, argv);
  if (a.help || a.command.empty()) { std::cout << kBanner << "\n" << help_text(); return 0; }
  if (a.command == "version" || a.command == "--version" || a.command == "-v") {
    std::cout << "wowmod-loadexe 1.0.0 (通用版本 / version-agnostic)\n";
    return 0;
  }
  if (a.command == "help") { std::cout << help_text(); return 0; }
  if (a.command == "init") return cmd_init(a);

  Session s;
  if (!prepare(a, &s)) {
    std::cerr << s.diag.render(false);
    return 1;
  }
  if (a.command == "detect") return cmd_detect(a, s);
  if (a.command == "validate") return cmd_validate(a, s);
  if (a.command == "plan") return cmd_plan(a, s);
  if (a.command == "scan") return cmd_scan(a, s);
  if (a.command == "adapt") return cmd_adapt(a, s);
  if (a.command == "discover") return cmd_discover(a, s);
  if (a.command == "launch") return cmd_launch(a, s);
  std::cerr << "未知命令: " << a.command << "\n\n" << help_text();
  return 2;
}
