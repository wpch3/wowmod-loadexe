// 版本探测：只从客户端文件本身读取信息，绝不内置版本号白名单。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "wowmod/json.hpp"
#include "wowmod/util.hpp"

namespace wowmod {

struct ClientInfo {
  bool valid = false;
  std::string exe_path;       // 绝对路径（POSIX 风格 '/'）
  std::string game_dir;       // 游戏根目录（exe 所在目录）
  std::string data_dir;       // 探测到的 Data 目录
  std::string version_string; // 例如 "3.3.5.12340" 或 "12.1.5.70783"
  int major = 0, minor = 0, patch = 0, build = 0;
  std::string product;        // .build.info 里的 Product
  std::string branch;         // .build.info 里的 Branch
  std::string build_key;
  std::string cdn_key;
  std::string arch = "unknown";     // x86 / x64 / arm64
  std::string storage = "unknown";  // casc / mpq / hybrid / unknown
  std::string portal;         // WTF/Config.wtf 里的 SET portal
  std::string realmlist;      // realmlist.wtf 内容（老客户端）
  std::vector<std::string> notes;

  Json to_json() const;
  std::string display() const;
};

// 从 "1.2.3.45678" / "1.2.3" / "45678" 解析出四段。build 永远是最后一段。
bool parse_version_string(const std::string& s, int* major, int* minor, int* patch, int* build);

// 解析 .build.info（TACT 的竖线分隔表）。
bool parse_build_info(const std::string& text, ClientInfo* out, std::string* err);

// 从内存里的 PE 映像读取版本资源 / 架构（跨平台，便于测试）。
bool parse_pe_metadata(const std::vector<uint8_t>& bytes, ClientInfo* out, std::string* err);

// 从 game_dir 的磁盘布局推断存储类型（看文件，不看版本号）。
std::string detect_storage_layout(const std::string& game_dir, std::string* data_dir);

// 读取 WTF/Config.wtf 与 realmlist.wtf。
void detect_server_settings(const std::string& game_dir, ClientInfo* out);

// 主入口：传入 exe 路径、游戏目录或仅根目录均可。
// exe_bytes_out 可选：把探测时读到的 exe 字节交给调用方复用（避免重复读大文件）。
ClientInfo detect_client(const std::string& path, Diagnostics* diag = nullptr,
                         std::vector<uint8_t>* exe_bytes_out = nullptr);

// 在 root 下递归查找名为 wow*.exe 的可执行文件（不假设 _retail_ 等目录名）。
std::vector<std::string> discover_client_exes(const std::string& root, int max_depth = 3);

// 用户可选的"展示覆盖"：某些私服 exe 被改过，读不到版本资源。
// 只影响展示与 when 过滤，绝不用于支持性判断。
void apply_display_overrides(ClientInfo* ci, const std::string& version, int build);

// PE 映像辅助：RVA <-> 文件偏移，供特征扫描使用。
struct PeImage {
  std::vector<uint8_t> bytes;
  uint16_t machine = 0;
  uint64_t image_base = 0;
  uint32_t resource_rva_ = 0;  // 资源目录 RVA（0 表示没有）
  struct Section { std::string name; uint32_t rva = 0, vsize = 0, raw_size = 0, raw_ptr = 0; bool executable = false; };
  std::vector<Section> sections;
  bool ok = false;

  bool load(const std::vector<uint8_t>& data, std::string* err);
  // 返回文件偏移，越界返回 nullopt。
  std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
  std::optional<uint32_t> offset_to_rva(uint32_t off) const;
};

}  // namespace wowmod
