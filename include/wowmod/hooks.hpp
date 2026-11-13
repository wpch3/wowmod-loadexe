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
  std::string module;               // 只在该模块里找（私服壳 exe + Wow_loader.dll 时很有用），空 = 全部
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
  std::string module;       // 命中所在的模块名（空 = 主 exe）
  size_t file_offset = 0;
  uint32_t rva = 0;
  size_t match_count = 0;
  std::string reason;
  Json to_json() const;
};

// 一个待扫描的二进制映像。私服常见结构：壳 exe 只导入 Wow_loader.dll，
// 真正的游戏代码（以及 FileDataID hook 点）在 DLL 里，必须一起扫描。
struct HookImage {
  std::string module;              // 空 = 主 exe；否则为 DLL 文件名
  std::vector<uint8_t> bytes;
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

// 收集要扫描的映像：主 exe + 配置里 hooks.scanTargets + 导入表里的加载层 DLL。
// 找不到附加 DLL 时只返回主 exe（不影响纯 VFS 模式）。
std::vector<HookImage> collect_hook_images(const Config& cfg, const ClientInfo& ci,
                                           const std::vector<uint8_t>& exe_bytes,
                                           Diagnostics* diag = nullptr);

// 在实际客户端二进制上做能力探测：谁的特征能唯一匹配，就用谁。
// 单映像版本（兼容旧调用）；多映像版本供壳 exe + 加载层 DLL 的客户端使用。
HookPlan plan_hooks(const Config& cfg, const ClientInfo& ci, const std::vector<uint8_t>& exe_bytes, Diagnostics* diag = nullptr);
HookPlan plan_hooks(const Config& cfg, const ClientInfo& ci, const std::vector<HookImage>& images, Diagnostics* diag = nullptr);

// 扫描并报告所有特征的匹配情况（wowmod scan 用）。
Json scan_report(const std::string& exe_path, const std::vector<HookDescriptor>& descriptors, Diagnostics* diag = nullptr);
// 多模块版本：壳 exe + 加载层 DLL 一起报告。
Json scan_report(const std::vector<HookImage>& images, const std::vector<HookDescriptor>& descriptors, Diagnostics* diag = nullptr);

}  // namespace wowmod
