// 特征扫描 + 数据驱动的 hook 点选择。
//
// 关键点：特征码不写在程序里，而是放在外部 patterns.json。
// 支持新客户端 = 增加一个数据条目，不需要重新编译加载器，也不存在"支持版本列表"。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "wowmod/config.hpp"
#include "wowmod/version.hpp"

namespace wowmod {

// IDA 风格字节特征： "48 8B ?? ?? E8 ??" / "str:\"World of Warcraft usage\""
class Pattern {
 public:
  std::vector<int> bytes;  // -1 = 通配符
  std::string source;

  static Pattern parse(const std::string& text, std::string* err = nullptr);
  bool valid() const { return !bytes.empty(); }
  size_t size() const { return bytes.size(); }
  std::optional<size_t> find(const std::vector<uint8_t>& haystack, size_t start = 0) const;
  std::vector<size_t> find_all(const std::vector<uint8_t>& haystack, size_t start = 0) const;
};

struct HookDescriptor {
  std::string name;
  std::string kind = "fileId";      // fileId | filePath
  std::string arch;                 // x64 / x86 / arm64，空 = 任意
  std::string result = "rax=pathPtr";
  std::string id_register = "rdx";  // 存放 FileDataID 的寄存器（由数据指定）
  std::string path_register;        // filePath 模式使用的寄存器
  Pattern pattern;
  int offset = 0;                   // 相对匹配起点的 hook 地址偏移
  int priority = 0;
  bool allow_multiple = false;
  std::vector<std::string> storage;
  When when;
  std::string note;
};

struct HookMatch {
  HookDescriptor descriptor;
  size_t file_offset = 0;
  uint32_t rva = 0;
  size_t match_count = 0;
  std::string reason;
  Json to_json() const;
};

struct HookPlan {
  std::string mode = "vfs";        // vfs | fileid | off
  std::vector<HookMatch> matches;
  std::string reason;
  Json to_json() const;
};

// 从 patterns.json 读取（支持 {"patterns": [...]} 或直接数组）。
std::vector<HookDescriptor> load_hook_patterns(const std::string& path, Diagnostics* diag = nullptr);
HookDescriptor hook_from_json(const Json& j, Diagnostics* diag = nullptr);

// 在实际客户端二进制上做能力探测：谁的特征能唯一匹配，就用谁。
HookPlan plan_hooks(const Config& cfg, const ClientInfo& ci, const std::vector<uint8_t>& exe_bytes, Diagnostics* diag = nullptr);

// 扫描并报告所有特征的匹配情况（wowmod scan 用）。
Json scan_report(const std::string& exe_path, const std::vector<HookDescriptor>& descriptors, Diagnostics* diag = nullptr);

}  // namespace wowmod
