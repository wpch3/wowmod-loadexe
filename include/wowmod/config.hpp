// 配置模型。所有"版本相关"的东西都是用户数据（可选过滤器），不是内置白名单。
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "wowmod/json.hpp"
#include "wowmod/util.hpp"
#include "wowmod/version.hpp"

namespace wowmod {

// 可选的适用范围。全部留空 = 匹配任何客户端（这是默认值）。
struct When {
  std::vector<int> builds;
  int min_build = 0, max_build = 0;
  std::vector<std::string> products;
  std::vector<std::string> storage;
  std::vector<std::string> arch;
  bool any() const;
  bool matches(const ClientInfo& ci) const;
  static When from_json(const Json& j);
  Json to_json() const;
};

struct ModPack {
  std::string name;
  std::string path;        // 绝对路径
  std::string root;        // 包内子目录，视为游戏根目录
  std::string manifest;    // 可选的 wowmod.manifest.json（绝对路径）
  bool enabled = true;
  int priority = 0;
  When when;
};

struct Rule {
  std::string match;       // 通配符（game-relative key）
  std::string replace;     // 绝对路径或空；空 = 屏蔽该路径
  int priority = 1000;
  When when;
};

struct ClientSettings {
  std::string exe;
  std::string game_dir;
  std::string version;   // 可选展示覆盖：私服 exe 读不到版本资源时用
  int build = 0;         // 可选展示覆盖：给 when 过滤用，不参与支持性判断
  std::string portal;
  std::string realmlist;
  std::vector<std::string> args;
  bool clear_cache = false;
};

struct HookSettings {
  std::string mode = "auto";     // auto | vfs | fileid | off
  std::string patterns;          // 兼容单文件写法（= pattern_files[0]）
  std::vector<std::string> pattern_files;  // 支持多个特征文件，新增适配不必改原文件
  bool allow_fallback = true;    // 找不到 hook 点时允许仅 VFS 启动
};

struct LogSettings {
  std::string file;
  bool verbose = false;
};

struct Config {
  int version = 1;
  std::string path;        // 配置文件本身
  std::string base_dir;    // 相对路径的基准
  ClientSettings client;
  std::vector<ModPack> mods;
  std::vector<std::string> mappings;
  std::vector<Rule> rules;
  HookSettings hooks;
  LogSettings log;

  static Config from_json(const Json& j, const std::string& config_path, Diagnostics* diag = nullptr);
  Json to_json() const;
};

// 读取配置（JSONC）。相对路径按配置文件所在目录解析。
bool load_config(const std::string& path, Config* out, Diagnostics* diag = nullptr);
// 生成一份可直接使用的示例配置文本。
std::string default_config_text(const std::string& game_dir);
// 检查配置里的路径/字段是否可用（不因"未知版本"报错）。
bool validate_config(const Config& cfg, Diagnostics* diag);

}  // namespace wowmod
