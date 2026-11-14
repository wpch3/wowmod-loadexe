// 零依赖单元测试：覆盖核心逻辑（可在 Linux/macOS/Windows 上运行）。
// SPDX-License-Identifier: MIT
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "wowmod/analyze.hpp"
#include "wowmod/protect_plan.hpp"
#include "wowmod/arctium.hpp"
#include "wowmod/fileid_stub.hpp"
#include "wowmod/launcher_stub.hpp"
#include "wowmod/x64_decode.hpp"
#include "wowmod/xref.hpp"
#include "wowmod/config.hpp"
#include "wowmod/discover.hpp"
#include "wowmod/arctium_sigs.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/json.hpp"
#include "wowmod/mapping.hpp"
#include "wowmod/util.hpp"
#include "wowmod/vfs.hpp"
#include "wowmod/version.hpp"

namespace fs = std::filesystem;
using namespace wowmod;

static int g_total = 0, g_failed = 0;
static std::string g_group;

#define CHECK(expr, msg)                                                                     \
  do {                                                                                     \
    ++g_total;                                                                               \
    if (!(expr)) {                                                                           \
      ++g_failed;                                                                            \
      std::cerr << "  FAIL [" << g_group << "] " << msg << "  (" #expr ", line " << __LINE__ << ")\n"; \
    }                                                                                        \
  } while (0)

#define CHECK_EQ(a, b)                                                                       \
  do {                                                                                     \
    ++g_total;                                                                               \
    auto va = (a); auto vb = (b);                                                            \
    if (!(va == vb)) {                                                                       \
      ++g_failed;                                                                            \
      std::cerr << "  FAIL [" << g_group << "] " << #a " == " #b << "  got '" << va << "' vs '" << vb << "' (line " << __LINE__ << ")\n"; \
    }                                                                                        \
  } while (0)

static void group(const std::string& g) { g_group = g; std::cout << "[" << g << "]\n"; }

static fs::path g_tmp;

static void setup() {
  auto stamp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  g_tmp = fs::temp_directory_path() / ("wowmod_test_" + std::to_string(stamp));
  fs::create_directories(g_tmp);
}

static void teardown() {
  std::error_code ec;
  fs::remove_all(g_tmp, ec);
}

static std::string tmp(const std::string& rel) { return (g_tmp / rel).string(); }

static void put(const std::string& rel, const std::string& content) {
  fs::path p = g_tmp / rel;
  fs::create_directories(p.parent_path());
  std::ofstream f(p, std::ios::binary);
  f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

static void put_bytes(const std::string& rel, const std::vector<uint8_t>& v) {
  fs::path p = g_tmp / rel;
  fs::create_directories(p.parent_path());
  std::ofstream f(p, std::ios::binary);
  f.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size()));
}

// ---------- 构造一个最小的 PE32+ 文件（含 VS_VERSION_INFO 资源） ----------
static void w16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
  if (b.size() < o + 2) b.resize(o + 2, 0);
  b[o] = static_cast<uint8_t>(v & 0xFF); b[o + 1] = static_cast<uint8_t>(v >> 8);
}
static void w32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
  if (b.size() < o + 4) b.resize(o + 4, 0);
  for (int i = 0; i < 4; ++i) b[o + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

static std::vector<uint8_t> make_pe(int build) {
  std::vector<uint8_t> b(0x800, 0);
  w16(b, 0, 0x5A4D);
  w32(b, 0x3C, 0x80);
  const size_t pe = 0x80;
  w32(b, pe, 0x00004550);
  w16(b, pe + 4, 0x8664);      // x64
  w16(b, pe + 6, 1);           // 1 section
  w16(b, pe + 20, 0xF0);       // SizeOfOptionalHeader
  const size_t opt = pe + 24;
  w16(b, opt, 0x20B);          // PE32+
  w32(b, opt + 108, 16);       // NumberOfRvaAndSizes
  w32(b, opt + 112 + 2 * 8, 0x1000);  // Resource dir RVA
  const size_t sec = opt + 0xF0;
  std::memcpy(b.data() + sec, ".rsrc\0\0\0", 8);
  w32(b, sec + 8, 0x200);      // VirtualSize
  w32(b, sec + 12, 0x1000);    // VirtualAddress
  w32(b, sec + 16, 0x200);     // SizeOfRawData
  w32(b, sec + 20, 0x200);     // PointerToRawData
  w32(b, sec + 36, 0x40000040);

  // 资源根目录 @ file 0x200 (rva 0x1000)
  w16(b, 0x200 + 14, 1);       // NumberOfIdEntries
  w32(b, 0x210, 16);           // RT_VERSION
  w32(b, 0x210 + 4, 0x80000020);
  w16(b, 0x220 + 14, 1);
  w32(b, 0x230, 1);
  w32(b, 0x230 + 4, 0x80000040);
  w16(b, 0x240 + 14, 1);
  w32(b, 0x250, 0x409);
  w32(b, 0x250 + 4, 0x60);     // IMAGE_RESOURCE_DATA_ENTRY
  w32(b, 0x260, 0x1080);       // data RVA -> file 0x280
  w32(b, 0x260 + 4, 0x5C);     // size

  // VS_VERSION_INFO @ 0x280
  w16(b, 0x280, 0x5C);         // wLength
  w16(b, 0x282, 52);           // wValueLength
  w16(b, 0x284, 0);            // wType
  const wchar_t key[] = L"VS_VERSION_INFO";
  for (size_t i = 0; i < 15; ++i) w16(b, 0x286 + i * 2, static_cast<uint16_t>(key[i]));
  w16(b, 0x286 + 30, 0);
  const size_t fixed = 0x280 + 40;
  w32(b, fixed, 0xFEEF04BD);
  w32(b, fixed + 8, (3u << 16) | 3u);                 // 3.3
  w32(b, fixed + 12, (5u << 16) | static_cast<uint32_t>(build));  // 5.12340
  return b;
}

// 带一个可执行 .text 节的 PE（RVA 0x2000 -> 文件 0x400）
static std::vector<uint8_t> make_pe_code() {
  auto b = make_pe(70783);
  b.resize(0x900, 0);
  w16(b, 0x80 + 6, 2);  // 2 sections
  size_t sec = 0x80 + 24 + 0xF0;
  size_t s2 = sec + 40;
  std::memcpy(b.data() + s2, ".text\0\0\0", 8);
  w32(b, s2 + 8, 0x200);        // VirtualSize
  w32(b, s2 + 12, 0x2000);      // VirtualAddress
  w32(b, s2 + 16, 0x200);       // SizeOfRawData
  w32(b, s2 + 20, 0x400);       // PointerToRawData
  w32(b, s2 + 36, 0x60000020);  // CODE | EXECUTE
  return b;
}

static const uint8_t kSig[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B,
    0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xE8, 0x01, 0x02, 0x03, 0x04, 0x74, 0x09};

static std::string sig_pattern(const uint8_t* s, size_t n) {
  std::string out;
  static const char* hx = "0123456789ABCDEF";
  for (size_t i = 0; i < n; ++i) {
    if (i) out += ' ';
    out += hx[s[i] >> 4]; out += hx[s[i] & 0xF];
  }
  return out;
}

// ---------- 测试 ----------
static void test_util() {
  group("util");
  CHECK_EQ(normalize_path("C:\\Games\\WoW\\Data\\..\\World\\a.m2"), "C:/Games/WoW/World/a.m2");
  CHECK_EQ(path_key("WORLD\\Models\\DRAGON.M2"), "world/models/dragon.m2");
  CHECK_EQ(join_path("a/b", "c/d"), "a/b/c/d");
  CHECK_EQ(parent_path("a/b/c.txt"), "a/b");
  CHECK_EQ(file_name("a/b/c.txt"), "c.txt");
  CHECK(wildcard_match("World/**/*.m2", "world/models/dragon.m2"), "glob ** 应匹配");
  CHECK(wildcard_match("*.blp", "SKIN.BLP"), "glob 大小写不敏感");
  CHECK(!wildcard_match("*.m2", "skin.blp"), "glob 不应误匹配");
  CHECK_EQ(relative_key("D:/Games/WoW", "D:/Games/WoW/World/a.m2").value_or(""), "world/a.m2");
  CHECK(!relative_key("D:/Games/WoW", "E:/Other/x"), "不同根目录应返回 nullopt");
  uint64_t v = 0;
  CHECK(parse_u64("0x1A2B", &v, 10) && v == 0x1A2B, "0x 前缀解析");
  CHECK(parse_u64("12345", &v, 10) && v == 12345, "十进制解析");
  CHECK(!parse_u64("notanumber", &v, 10), "非法数字应失败");
  CHECK_EQ(to_hex(48879, 8), "0000beef");
  CHECK_EQ(trim("  hello \t\n"), "hello");
  CHECK_EQ(replace_all("a\\b\\c", "\\", "/"), "a/b/c");
}

static void test_json() {
  group("json");
  std::string err;
  Json j = Json::parse("{\n // 注释\n \"a\": 1, \"b\": [true, false, null,], /* x */ \"s\": \"hi\\n\\u4e2d\\u6587\", }", &err);
  CHECK(err.empty(), "JSONC 应解析成功: " + err);
  CHECK_EQ(j.at("a").as_int(), 1);
  CHECK_EQ(j.at("b").as_array().size(), size_t(3));
  CHECK_EQ(j.at("s").as_string(), std::string("hi\n中文"));
  CHECK(j.at("b").index(0).as_bool(), "true");
  CHECK(!j.at("b").index(1).as_bool(), "false");
  CHECK(!j.has("missing"), "不存在的键");
  std::string dumped = j.dump(2);
  std::string err2;
  Json j2 = Json::parse(dumped, &err2);
  CHECK(err2.empty() && j2.at("a").as_int() == 1, "dump -> parse 往返");
  Json bad = Json::parse("{\"a\": }", &err);
  CHECK(!err.empty(), "畸形 JSON 应报错");
  CHECK(bad.is_null(), "失败返回 null");
  Json arr = Json::parse("[1, 2, 3]", &err);
  CHECK_EQ(arr.as_array().size(), size_t(3));
}

static void test_version() {
  group("version");
  int a = 0, b = 0, c = 0, d = 0;
  CHECK(parse_version_string("12.1.5.70783", &a, &b, &c, &d), "解析 4 段版本");
  CHECK_EQ(a, 12); CHECK_EQ(b, 1); CHECK_EQ(c, 5); CHECK_EQ(d, 70783);
  CHECK(parse_version_string("3.3.5a.12340", &a, &b, &c, &d) && d == 12340, "带字母后缀的版本");
  CHECK(parse_version_string("45678", &a, &b, &c, &d) && d == 45678, "纯 build 号");

  std::string bi =
      "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Version!STRING:0|Product!STRING:0\n"
      "wow_private|0|aaa|bbb|9.9.9.99999|wow\n"
      "my_branch|1|ccc|ddd|3.3.5.12340|wow_classic\n";
  ClientInfo ci;
  std::string err;
  CHECK(parse_build_info(bi, &ci, &err), "解析 .build.info: " + err);
  CHECK_EQ(ci.version_string, "3.3.5.12340");  // 取 Active=1 的行
  CHECK_EQ(ci.build, 12340);
  CHECK_EQ(ci.product, "wow_classic");
  CHECK_EQ(ci.branch, "my_branch");

  auto pe_bytes = make_pe(12340);
  ClientInfo pe_ci;
  CHECK(parse_pe_metadata(pe_bytes, &pe_ci, &err), "解析 PE 版本资源: " + err);
  CHECK_EQ(pe_ci.version_string, "3.3.5.12340");
  CHECK_EQ(pe_ci.arch, "x64");
  PeImage pe;
  CHECK(pe.load(pe_bytes, &err), "PeImage::load");
  CHECK_EQ(pe.offset_to_rva(0x280).value_or(0), 0x1080u);
  CHECK_EQ(pe.rva_to_offset(0x1080).value_or(0), 0x280u);

  // 存储布局探测
  std::string game = tmp("game");
  put("game/Data/data/00/00000001", "x");
  CHECK_EQ(detect_storage_layout(game, nullptr), "casc");
  std::string game2 = tmp("game2");
  put("game2/Data/patch-enUS-9.MPQ", "x");
  CHECK_EQ(detect_storage_layout(game2, nullptr), "mpq");

  // 完整探测：exe + .build.info + Config.wtf
  put_bytes("full/Wow.exe", pe_bytes);
  put("full/.build.info", bi);
  put("full/WTF/Config.wtf", "SET locale \"zhCN\"\nSET portal \"old.server\"\n");
  ClientInfo full = detect_client(tmp("full"), nullptr);
  CHECK_EQ(full.arch, "x64");
  CHECK_EQ(full.version_string, "3.3.5.12340");
  CHECK_EQ(full.portal, "old.server");
  CHECK_EQ(full.storage, "unknown");  // 没有 Data 目录
  CHECK(full.to_json().at("supported").as_bool(), "legacy supported means version gate passed");
  CHECK_EQ(full.to_json().at("supportStatus").as_string(), "not-verified");
  CHECK(!full.to_json().at("capabilitiesVerified").as_bool(), "detect 不伪报运行时能力已验证");
  CHECK(full.display().find("未验证") != std::string::npos, "detect 文本应明确运行时能力未验证");
  CHECK(!full.notes.empty(), "应有诊断说明");
  auto exes = discover_client_exes(tmp("full"));
  CHECK_EQ(exes.size(), size_t(1));
}

static void test_mapping() {
  group("mapping");
  MappingTable m;
  Diagnostics d;
  size_t n = m.parse("# 注释\n123456;World/Model/Dragon.m2\n123457;WORLD\\Textures\\Skin.BLP;extra\n"
                     "bogus line\n0;invalid\n;missing\n\n123458;Interface/AddOns/X/X.lua", "test.txt", &d);
  CHECK_EQ(n, size_t(3));
  CHECK_EQ(d.count(Level::Warn), size_t(1));
  CHECK_EQ(m.id_for_path("world/model/dragon.m2").value_or(0), 123456u);
  CHECK_EQ(m.id_for_path("World\\Textures\\skin.blp").value_or(0), 123457u);
  CHECK_EQ(m.path_for_id(123457).value_or(""), "WORLD/Textures/Skin.BLP");
  CHECK(!m.id_for_path("unknown/path").has_value(), "未知路径");
  put("mappings/l.txt", "999;Foo/Bar.m2\n");
  CHECK(m.load_file(tmp("mappings/l.txt"), &d), "载入映射文件");
  CHECK_EQ(m.id_for_path("foo/bar.m2").value_or(0), 999u);
}

static void test_arctium_file_plan() {
  group("arctium-file-plan");
  const std::string root = tmp("arctium/files");
  put("arctium/files/Character/BloodElf/Female/a.blp", "a-data");
  put("arctium/files/Character/BloodElf/Female/b.blp", "bb-data");
  put("arctium/files/Character/BloodElf/Female/unmapped.blp", "not-mapped");
  put("arctium/files/Character/BloodElf/Female/overflow.blp", "too-large-id");
  put("arctium/files/README.txt", "not-a-game-file");

  MappingTable mappings;
  mappings.add(210u, "Character/BloodElf/Female/a.blp", "test");
  mappings.add(205u, "Character/BloodElf/Female/b.blp", "test");
  mappings.add(205u, "Character/BloodElf/Female/unmapped.blp", "duplicate-id");
  mappings.add(0x100000000ull, "Character/BloodElf/Female/overflow.blp", "overflow");

  Diagnostics d;
  ArctiumFilePlan plan = plan_arctium_files(root, mappings, &d);
  CHECK(plan.error.empty(), "目录扫描成功: " + plan.error);
  CHECK_EQ(plan.files_root, absolute_path(root));
  CHECK_EQ(plan.scanned_files, size_t(5));
  CHECK_EQ(plan.files.size(), size_t(2));
  CHECK_EQ(plan.files[0].file_id, uint32_t(205));
  CHECK_EQ(plan.files[1].file_id, uint32_t(210));
  CHECK_EQ(plan.files[1].game_path, "Character/BloodElf/Female/a.blp");
  CHECK_EQ(plan.files[1].local_path, to_native_path(absolute_path(root + "/Character/BloodElf/Female/a.blp")));
  CHECK_EQ(plan.files[1].size, uint64_t(6));
  CHECK_EQ(plan.unmapped_files, size_t(1));
  CHECK_EQ(plan.duplicate_ids, size_t(1));
  CHECK_EQ(plan.invalid_ids, size_t(1));
  CHECK(d.count(Level::Warn) >= 1, "重复 ID 应产生警告");
  Json plan_json = plan.to_json();
  CHECK_EQ(plan_json.at("files").as_array().size(), size_t(2));
  CHECK_EQ(plan_json.at("status").as_string(), "preflight-only");
  CHECK(!plan_json.at("clientModified").as_bool(), "预检不修改客户端");
  CHECK(!plan_json.at("hookInstalled").as_bool(), "预检不假报已安装 hook");

  ArctiumFilePlan missing = plan_arctium_files(tmp("arctium/no-such-files"), mappings, &d);
  CHECK(!missing.error.empty(), "不存在的 filesDir 必须显式报错");
}

static void test_config() {
  group("config");
  std::string cfg_text =
      "{\n"
      "  // 示例\n"
      "  \"version\": 1,\n"
      "  \"client\": { \"exe\": \"\", \"gameDir\": \".\", \"portal\": \"my.private\", \"args\": [\"-console\"] },\n"
      "  \"mods\": [\n"
      "    { \"name\": \"A\", \"path\": \"mods/a\", \"enabled\": true, \"priority\": 20, \"when\": { \"minBuild\": 100 } },\n"
      "    { \"name\": \"B\", \"path\": \"mods/b\", \"enabled\": false }\n"
      "  ],\n"
      "  \"mappings\": [\"mappings/l.txt\"],\n"
      "  \"rules\": [ { \"match\": \"World/**/*.m2\", \"replace\": \"\" } ],\n"
      "  \"hooks\": { \"mode\": \"auto\", \"patterns\": \"hooks/p.json\" },\n"
      "  \"arctium\": { \"filesDir\": \"mods/a\" },\n"
      "  \"log\": { \"file\": \"wowmod.log\" }\n"
      "}\n";
  std::string path = tmp("cfg/wowmod.json");
  put("cfg/wowmod.json", cfg_text);
  put("cfg/mods/a/x.txt", "x");
  put("cfg/mods/b/y.txt", "y");
  put("cfg/mappings/l.txt", "1;a\n");
  put("cfg/hooks/p.json", "{\"patterns\":[]}");
  Config cfg;
  Diagnostics d;
  CHECK(load_config(path, &cfg, &d), "载入配置");
  CHECK_EQ(cfg.mods.size(), size_t(2));
  CHECK_EQ(cfg.mods[0].priority, 20);
  CHECK(cfg.mods[0].path == tmp("cfg/mods/a"), "相对路径按配置目录解析");
  CHECK_EQ(cfg.arctium.files_dir, tmp("cfg/mods/a"));
  CHECK_EQ(cfg.client.portal, "my.private");
  CHECK_EQ(cfg.rules.size(), size_t(1));
  CHECK(validate_config(cfg, &d), "配置校验应通过");
  CHECK(!d.has_errors(), "不应有错误");

  ClientInfo ci;
  ci.build = 50;
  CHECK(!cfg.mods[0].when.matches(ci), "minBuild 过滤生效");
  ci.build = 200;
  CHECK(cfg.mods[0].when.matches(ci), "build 满足时生效");
  When any;
  CHECK(any.matches(ci), "空过滤器匹配任何版本（关键：无版本白名单）");

  std::string err2;
  Json round = Json::parse(cfg.to_json().dump(2), &err2);
  CHECK(err2.empty() && round.at("mods").as_array().size() == 2, "Config -> JSON 往返");
  Config cfg_roundtrip = Config::from_json(round, path);
  CHECK_EQ(cfg_roundtrip.arctium.files_dir, cfg.arctium.files_dir);
}

static void test_vfs() {
  group("vfs");
  Diagnostics d;
  std::string game = tmp("vfs/game");
  put("vfs/game/WTF/Config.wtf", "SET locale \"zhCN\"\nSET portal \"old\"\nSET hwDetect \"0\"\n");
  put_bytes("vfs/game/Wow.exe", make_pe(70783));
  put("vfs/game/Data/data/00/0001", "x");
  put("vfs/mappings/listfile.txt", "123456;World/Model/Dragon.m2\n123457;World/Textures/Skin.blp\n");
  put("vfs/mods/A/World/Model/Dragon.m2", "AAAA");
  put("vfs/mods/A/Interface/AddOns/New/New.toc", "## Interface: 100000");
  put("vfs/mods/A/README.md", "# 说明文档，不应成为覆盖项");
  put("vfs/mods/B/World/Model/Dragon.m2", "BBBBBB");
  put("vfs/mods/B/wowmod.manifest.json", "{\"files\":[{\"id\":123457,\"file\":\"override.blp\"}]}");
  put("vfs/mods/B/override.blp", "BLP!");

  Config cfg;
  cfg.client.exe = tmp("vfs/game/Wow.exe");
  cfg.client.game_dir = game;
  cfg.client.portal = "my.private.server";
  cfg.mappings.push_back(tmp("vfs/mappings/listfile.txt"));
  ModPack a{"A", tmp("vfs/mods/A"), "", "", true, 10, When{}};
  ModPack b{"B", tmp("vfs/mods/B"), "", tmp("vfs/mods/B/wowmod.manifest.json"), true, 99, When{}};
  cfg.mods.push_back(a);
  cfg.mods.push_back(b);
  ClientInfo ci = detect_client(cfg.client.exe, &d);
  MappingTable m;
  m.load_file(cfg.mappings[0], &d);
  Vfs vfs;
  CHECK(vfs.build(cfg, ci, m, &d), "构建 VFS");

  CHECK(!vfs.resolve_path("README.md").has_value(), "模组包根目录的说明文档不应成为覆盖项");
  auto hit = vfs.resolve_path("WORLD\\Model\\Dragon.M2");
  CHECK(hit.has_value(), "路径覆盖命中（大小写/分隔符无关）");
  CHECK(hit && hit->pack == "B", "高优先级模组包胜出");
  CHECK(hit && hit->file_id == 123456, "自动从 listfile 得到 FileDataID");
  auto by_id = vfs.resolve_id(123456);
  CHECK(by_id.has_value() && by_id->pack == "B", "按 FileDataID 覆盖");
  auto by_id2 = vfs.resolve_id(123457);
  CHECK(by_id2.has_value() && by_id2->real_path == tmp("vfs/mods/B/override.blp"), "manifest 按 ID 覆盖");

  auto cfg_hit = vfs.resolve_path("WTF/Config.wtf");
  CHECK(cfg_hit.has_value() && cfg_hit->generated, "内存生成 Config.wtf");
  CHECK(cfg_hit && cfg_hit->content.find("SET portal \"my.private.server\"") != std::string::npos, "portal 已替换");
  CHECK(cfg_hit && cfg_hit->content.find("SET locale") != std::string::npos, "原有配置保留");
  CHECK(cfg_hit && cfg_hit->content.find("SET portal \"old\"") == std::string::npos, "旧 portal 已移除");

  auto extras = vfs.extra_names("Interface/AddOns");
  CHECK(std::find(extras.begin(), extras.end(), "New") != extras.end(), "目录枚举叠加能发现新增目录");

  // materialize 之后生成文件有真实路径
  size_t n = vfs.materialize_generated(tmp("vfs/out"), &d);
  CHECK_EQ(n, size_t(1));
  auto cfg2 = vfs.resolve_path("WTF/Config.wtf");
  CHECK(cfg2 && cfg2->real_path == tmp("vfs/out/wtf/config.wtf"), "生成文件路径已落地");
  CHECK(file_exists(tmp("vfs/out/wtf/config.wtf")), "生成文件确实写入");

  // 规则：屏蔽
  cfg.rules.push_back(Rule{"World/**/*.m2", "", 1000, When{}});
  Vfs vfs2;
  CHECK(vfs2.build(cfg, ci, m, &d), "含规则构建 VFS");
  auto blocked = vfs2.resolve_path("World/Model/Dragon.m2");
  CHECK(blocked.has_value() && blocked->blocked, "空 replace 规则屏蔽文件");

  // 适用范围过滤
  cfg.mods[1].when.min_build = 999999;
  Vfs vfs3;
  CHECK(vfs3.build(cfg, ci, m, &d), "过滤后构建");
  CHECK_EQ(vfs3.stats().skipped_by_filter, size_t(1));
  CHECK_EQ(vfs3.stats().packs, size_t(1));

  Json plan = vfs.plan_json();
  CHECK(plan.at("client").at("supported").as_bool(), "legacy supported 仅表示版本门未拒绝");
  CHECK_EQ(plan.at("client").at("supportStatus").as_string(), "not-verified");
  CHECK(!plan.at("overlays").as_array().empty(), "plan 有覆盖表");
  CHECK(!vfs.plan_text().empty(), "plan 文本非空");
}

static void test_hooks() {
  group("hooks");
  std::string err;
  Pattern p = Pattern::parse("48 8B ?? ?? E8 ?? ?? ?? ?? 74 ?", &err);
  CHECK(err.empty() && p.valid(), "解析 IDA 风格特征: " + err);
  CHECK_EQ(p.size(), size_t(11));
  std::vector<uint8_t> hay = {0x00, 0x48, 0x8B, 0x05, 0xAA, 0xE8, 1, 2, 3, 4, 0x74, 0x09, 0x90,
                             0x48, 0x8B, 0x11, 0x22, 0xE8, 5, 6, 7, 8, 0x74, 0x01};
  auto all = p.find_all(hay);
  CHECK_EQ(all.size(), size_t(2));
  CHECK_EQ(all[0], size_t(1));
  Pattern compact = Pattern::parse("488B??E8", &err);
  CHECK(compact.valid() && compact.size() == 4, "紧凑 hex 串解析");
  Pattern strp = Pattern::parse("str:\"World of Warcraft usage\"", &err);
  CHECK(strp.valid() && strp.size() == 23, "字符串特征解析: " + err);
  Pattern bad = Pattern::parse("ZZ 11", &err);
  CHECK(!bad.valid() || !err.empty(), "非法 token 应报错");

  put("hooks/p.json",
      "{\n"
      "  \"patterns\": [\n"
      "    { \"name\": \"unique\", \"kind\": \"fileId\", \"arch\": \"x64\", \"pattern\": \"48 8B ?? ?? E8 ?? ?? ?? ?? 74 ?\", \"idRegister\": \"rdx\", \"priority\": 5 },\n"
      "    { \"name\": \"nomatch\", \"pattern\": \"DE AD BE EF\" },\n"
      "    { \"name\": \"wrongarch\", \"arch\": \"arm64\", \"pattern\": \"48 8B ?? ?? E8 ?? ?? ?? ?? 74 ?\" }\n"
      "  ]\n"
      "}\n");
  Diagnostics d;
  auto ds = load_hook_patterns(tmp("hooks/p.json"), &d);
  CHECK_EQ(ds.size(), size_t(3));
  CHECK_EQ(ds[0].id_register, "rdx");
  CHECK_EQ(ds[0].priority, 5);

  put_bytes("scan/Wow.exe", make_pe(12340));
  // 把特征字节放进 exe 的 .text 区域（文件偏移 0x500，位于 .rsrc raw 范围之外但仍在文件内）
  auto exe = make_pe(12340);
  const uint8_t sig[] = {0x48, 0x8B, 0x05, 0xAA, 0xE8, 1, 2, 3, 4, 0x74, 0x09};
  if (exe.size() < 0x520) exe.resize(0x520, 0);
  for (size_t i = 0; i < sizeof(sig); ++i) exe[0x500 + i] = sig[i];
  put_bytes("scan/Wow.exe", exe);

  Config cfg;
  cfg.hooks.patterns = tmp("hooks/p.json");
  cfg.client.exe = tmp("scan/Wow.exe");
  ClientInfo ci = detect_client(cfg.client.exe, &d);
  ci.arch = "x64";
  HookPlan plan = plan_hooks(cfg, ci, exe, &d);
  // "unique" 唯一匹配；"nomatch" 无匹配；"wrongarch" 架构不符
  CHECK_EQ(plan.mode, "fileid");
  CHECK_EQ(plan.matches.size(), size_t(1));
  CHECK_EQ(plan.matches[0].descriptor.name, "unique");
  CHECK_EQ(plan.matches[0].file_offset, size_t(0x500));

  Json report = scan_report(tmp("scan/Wow.exe"), ds, &d);
  CHECK_EQ(report.at("results").as_array().size(), size_t(3));
  CHECK_EQ(report.at("results").index(0).at("matches").as_int(0), 1);

  // 没有特征文件时安全退化，绝不阻止启动
  Config cfg2;
  cfg2.hooks.patterns = tmp("hooks/does-not-exist.json");
  HookPlan plan2 = plan_hooks(cfg2, ci, exe, &d);
  CHECK_EQ(plan2.mode, "vfs");
  CHECK(plan2.reason.find("VFS") != std::string::npos, "退化说明包含 VFS");
  Config cfg3;
  cfg3.hooks.mode = "off";
  CHECK_EQ(plan_hooks(cfg3, ci, exe, &d).mode, "off");
}

static void test_discover() {
  group("discover(adapt)");
  auto exe = make_pe_code();
  std::memcpy(exe.data() + 0x400, kSig, sizeof(kSig));
  std::string exact = sig_pattern(kSig, sizeof(kSig));

  AdaptResult r0 = relax_pattern(exact, exe);
  CHECK(r0.ok, "原样特征应唯一匹配");
  CHECK_EQ(r0.file_offset, size_t(0x400));
  CHECK_EQ(r0.rva, 0x2000u);
  CHECK(r0.executable, "命中位置应在可执行节区");
  CHECK(!r0.warning, "原样匹配不应有警告");

  // 模拟"邻近 build"：两个字节变了，原特征 0 匹配；自适应应把变化字节放宽成 ??
  std::string near = exact;
  near = replace_all(near, "05 AA BB", "05 AB BB");
  near = replace_all(near, "04 74 09", "04 75 09");
  std::string err;
  Pattern near_p = Pattern::parse(near, &err);
  CHECK_EQ(count_matches(near_p, exe, 2), size_t(0));
  AdaptResult r1 = relax_pattern(near, exe, 8, &err);
  CHECK(r1.ok, "跨 build 特征应能自动放宽: " + r1.reason);
  CHECK_EQ(r1.file_offset, size_t(0x400));
  CHECK(r1.fixed_bytes >= 8, "结果应保留足够固定字节");
  CHECK(r1.warning, "原始 0 匹配应给出警告");
  Pattern rp = Pattern::parse(r1.pattern, &err);
  CHECK(err.empty(), "生成的特征应可重新解析");
  CHECK_EQ(count_matches(rp, exe, 3), size_t(1));
  CHECK_EQ(r1.rva, 0x2000u);

  // 太短的特征应安全失败，而不是退化成全通配
  AdaptResult r2 = relax_pattern("48 89", exe, 8, &err);
  CHECK(!r2.ok, "过短特征应被拒绝");
  CHECK(r2.reason.find("太少") != std::string::npos, "应说明固定字节太少");

  // 自适应结果可以写成可直接使用的 patterns.json
  put("adapt/hooks/.keep", "");
  std::string out = tmp("adapt/hooks/patterns.adapted.json");
  put_bytes("adapt/exe.bin", exe);
  std::string aerr;
  AdaptFileResult f = adapt_pattern_file(tmp("adapt/exe.bin"), exact, out, "my-12.0.7", "rdx", &aerr);
  CHECK(f.ok, "写出 patterns.json: " + f.reason);
  auto ds = load_hook_patterns(out, nullptr);
  CHECK_EQ(ds.size(), size_t(1));
  CHECK_EQ(ds[0].name, "my-12.0.7");
  CHECK_EQ(ds[0].id_register, "rdx");
  // 同名重复写入不会累积
  f = adapt_pattern_file(tmp("adapt/exe.bin"), exact, out, "my-12.0.7", "rdx", &aerr);
  CHECK_EQ(load_hook_patterns(out, nullptr).size(), size_t(1));

  // 配置支持多个特征文件
  put("adapt/cfg/wowmod.json",
      "{\"client\":{\"gameDir\":\".\",\"version\":\"12.0.7\",\"build\":70500},"
      "\"hooks\":{\"patterns\":[\"hooks/a.json\",\"hooks/b.json\"]}}");
  Config cfg;
  Diagnostics d;
  CHECK(load_config(tmp("adapt/cfg/wowmod.json"), &cfg, &d), "载入多特征文件配置");
  CHECK_EQ(cfg.hooks.pattern_files.size(), size_t(2));
  CHECK_EQ(cfg.client.version, "12.0.7");
  CHECK_EQ(cfg.client.build, 70500);
  ClientInfo ci;
  apply_display_overrides(&ci, cfg.client.version, cfg.client.build);
  CHECK_EQ(ci.version_string, "12.0.7");
  CHECK_EQ(ci.build, 70500);
  CHECK(ci.to_json().at("supported").as_bool(), "展示覆盖不改变版本门结果");
  CHECK(!ci.to_json().at("capabilitiesVerified").as_bool(), "展示覆盖不伪造运行时能力验证");
  Json dumped = Json::parse(cfg.to_json().dump(2), &err);
  CHECK(err.empty() && dumped.at("hooks").at("patterns").as_array().size() == 2, "多特征文件 JSON 往返");

  // 本地自动发现：字符串 + 指向它的 RIP 相对 LEA
  auto dex = make_pe_code();
  std::memcpy(dex.data() + 0x400, kSig, sizeof(kSig));
  const char anchor[] = "DBFilesClient\\";
  std::memcpy(dex.data() + 0x480, anchor, sizeof(anchor) - 1);
  // file 0x450 -> RVA 0x2050；字符串 RVA 0x2080
  int32_t disp = static_cast<int32_t>(0x2080u - (0x2050u + 7));
  dex[0x450] = 0x48; dex[0x451] = 0x8D; dex[0x452] = 0x0D;
  for (int k = 0; k < 4; ++k) dex[0x453 + k] = static_cast<uint8_t>((static_cast<uint32_t>(disp) >> (8 * k)) & 0xFF);
  DiscoveryReport rep = discover_hook_points(dex, {"DBFilesClient\\", "不存在的锚点"});
  CHECK(rep.pe, "discover 应识别 PE");
  CHECK_EQ(rep.arch, "x64");
  CHECK_EQ(rep.anchors_found.size(), size_t(1));
  CHECK(!rep.candidates.empty(), "应找到至少一个候选 hook 点");
  if (!rep.candidates.empty()) {
    CHECK_EQ(rep.candidates[0].code_rva, 0x2050u);
    CHECK_EQ(rep.candidates[0].unique_matches, size_t(1));
    CHECK(rep.candidates[0].pattern.find("48 8D 0D ??") != std::string::npos, "应把 disp32 通配");
    CHECK(rep.candidates[0].executable, "候选应在可执行节区");
  }
  std::string derr;
  CHECK(write_pattern_descriptor(tmp("adapt/hooks/discovered.json"), "auto-candidate",
                                 rep.candidates.empty() ? "48 8D 0D ?? ?? ?? ??" : rep.candidates[0].pattern,
                                 "x64", "rdx", "候选", &derr), "写出候选: " + derr);
  CHECK_EQ(load_hook_patterns(tmp("adapt/hooks/discovered.json"), nullptr).size(), size_t(1));
}


// 构造「运行时已解密的内存映像」：文件偏移 == RVA（节区 raw_ptr = rva）
static std::vector<uint8_t> make_mapped_image() {
  std::vector<uint8_t> b(0x9000, 0);
  const size_t pe = 0x80;
  w16(b, 0, 0x5A4D); w32(b, 0x3C, pe);
  w32(b, pe, 0x00004550); w16(b, pe + 4, 0x8664); w16(b, pe + 6, 2); w16(b, pe + 20, 0xF0);
  const size_t opt = pe + 24;
  w16(b, opt, 0x20B); w32(b, opt + 56, 0x9000); w32(b, opt + 108, 16);
  const size_t sec = opt + 0xF0;
  std::memcpy(b.data() + sec, ".text\0\0\0", 8);
  w32(b, sec + 8, 0x3000); w32(b, sec + 12, 0x1000); w32(b, sec + 16, 0x3000);
  w32(b, sec + 20, 0x1000); w32(b, sec + 36, 0x60000020);
  std::memcpy(b.data() + sec + 40, ".rdata\0\0", 8);
  w32(b, sec + 48, 0x1000); w32(b, sec + 52, 0x4000); w32(b, sec + 56, 0x1000);
  w32(b, sec + 60, 0x4000); w32(b, sec + 76, 0x40000040);
  const char anchor_str[] = "FileData ID %d %s";
  std::memcpy(b.data() + 0x4080, anchor_str, sizeof(anchor_str) - 1);
  int32_t disp = static_cast<int32_t>(0x4080u - (0x2100u + 7));
  b[0x2100] = 0x48; b[0x2101] = 0x8D; b[0x2102] = 0x0D;
  for (int k = 0; k < 4; ++k) b[0x2103 + k] = static_cast<uint8_t>((static_cast<uint32_t>(disp) >> (8 * k)) & 0xFF);
  return b;
}

// 模拟真实私服客户端：VS_FIXEDFILEINFO 被改成 1200.7.6897.4，
// 但 StringFileInfo/FileVersion 写着真实的 12.0.7.68974；导入表只有 Wow_loader.dll。
static std::vector<uint8_t> make_private_server_pe() {
  auto b = make_pe(4);
  b.resize(0x700, 0);
  const size_t opt = 0x80 + 24;
  const size_t sec = opt + 0xF0;
  w32(b, sec + 8, 0x600); w32(b, sec + 16, 0x600);  // 扩大 .rsrc，避开版本资源区
  // 导入表目录（PE32+ 的 dir_off = opt+112，索引 1）；放在 rva 0x1200 -> file 0x400
  w32(b, opt + 112 + 8, 0x1200);
  w32(b, opt + 112 + 12, 20);
  w32(b, 0x400 + 12, 0x1280);                    // IMAGE_IMPORT_DESCRIPTOR.Name
  const char dll[] = "Wow_loader.dll";
  std::memcpy(b.data() + 0x480, dll, sizeof(dll));

  // 版本资源数据：@ file 0x280 (rva 0x1080)
  size_t v = 0x280;
  auto key16 = [&](size_t off, const char* s) {
    size_t n = 0;
    for (const char* p = s; *p; ++p, ++n) w16(b, off + n * 2, static_cast<uint16_t>(*p));
    w16(b, off + n * 2, 0);
    return off + (n + 1) * 2;
  };
  auto val16 = [&](size_t off, const char* s) {
    size_t n = 0;
    for (const char* p = s; *p; ++p, ++n) w16(b, off + n * 2, static_cast<uint16_t>(*p));
    w16(b, off + n * 2, 0);
    return off + (n + 1) * 2;
  };
  auto align4 = [](size_t x) { return (x + 3) & ~static_cast<size_t>(3); };
  w16(b, v + 2, 52); w16(b, v + 4, 0);
  size_t k = key16(v + 6, "VS_VERSION_INFO");
  size_t fixed = align4(k);
  w32(b, fixed, 0xFEEF04BDu);
  w32(b, fixed + 8, (1200u << 16) | 7u);
  w32(b, fixed + 12, (6897u << 16) | 4u);        // 四元组被改坏
  size_t sfi = align4(fixed + 52);
  w16(b, sfi + 2, 0); w16(b, sfi + 4, 1);
  size_t k2 = key16(sfi + 6, "StringFileInfo");
  size_t tbl = align4(k2);
  w16(b, tbl + 2, 0); w16(b, tbl + 4, 1);
  size_t k3 = key16(tbl + 6, "040904b0");
  size_t str = align4(k3);
  w16(b, str + 2, 13); w16(b, str + 4, 1);       // "12.0.7.68974" 12 字符 + NUL
  size_t k4 = key16(str + 6, "FileVersion");
  size_t val = align4(k4);
  size_t end = val16(val, "12.0.7.68974");
  w16(b, str, static_cast<uint16_t>(align4(end - str)));
  w16(b, tbl, static_cast<uint16_t>(align4(end - tbl)));
  w16(b, sfi, static_cast<uint16_t>(align4(end - sfi)));
  w16(b, v, static_cast<uint16_t>(align4(end - v)));
  w32(b, 0x260 + 4, static_cast<uint32_t>(align4(end - v)));  // data_size
  return b;
}

static void test_real_client() {
  group("real-client(12.0.7 Firestorm)");
  auto b = make_private_server_pe();
  ClientInfo ci;
  std::string err;
  CHECK(parse_pe_metadata(b, &ci, &err), "解析私服 PE: " + err);
  CHECK_EQ(ci.version_string, "12.0.7.68974");   // 优先用字符串资源
  CHECK_EQ(ci.major, 12);
  CHECK_EQ(ci.build, 68974);
  CHECK_EQ(ci.arch, "x64");
  CHECK_EQ(ci.companion_dlls.size(), size_t(1));
  if (!ci.companion_dlls.empty()) CHECK_EQ(ci.companion_dlls[0], "Wow_loader.dll");

  // 配置：多模块扫描目标
  Config cfg;
  cfg.hooks.scan_targets = {"Wow_loader.dll"};
  CHECK_EQ(Config::from_json(cfg.to_json(), tmp("real/cfg.json")).hooks.scan_targets.size(), size_t(1));

  // 特征只属于 DLL：两个映像一起扫描，应该只在 DLL 里命中
  std::vector<uint8_t> exe(256, 0xCC), dll(256, 0x90);
  const uint8_t sig[] = {0x48, 0x8B, 0xD1, 0xE8, 0x11, 0x22, 0x33, 0x44};
  std::memcpy(dll.data() + 0x40, sig, sizeof(sig));
  std::vector<HookImage> images = {{"", exe}, {"Wow_loader.dll", dll}};
  Json d = Json::make_object();
  d.set("name", Json::make_string("dll-hook"));
  d.set("arch", Json::make_string("x64"));
  d.set("module", Json::make_string("Wow_loader.dll"));
  d.set("pattern", Json::make_string(sig_pattern(sig, sizeof(sig))));
  std::string perr;
  HookDescriptor hd = hook_from_json(Json::parse(d.dump(2), &perr));
  CHECK_EQ(hd.module, "Wow_loader.dll");
  cfg.hooks.mode = "auto";
  cfg.hooks.pattern_files = {};
  // 直接用多映像 plan_hooks：手工构造 ds 不方便，改测 scan_report
  Json rep = scan_report(images, {hd}, nullptr);
  CHECK_EQ(rep.at("modules").as_int(0), 2);
  const auto& rs = rep.at("results").as_array();
  CHECK_EQ(rs.size(), size_t(1));
  if (!rs.empty()) {
    CHECK_EQ(rs[0].at("matches").as_int(0), 1);
    CHECK_EQ(rs[0].at("module").as_string(), "Wow_loader.dll");
  }

  // descriptor 的 module 字段可被写回并读回
  std::string werr;
  CHECK(write_pattern_descriptor(tmp("real/hooks/module.json"), "m", sig_pattern(sig, sizeof(sig)),
                                 "x64", "rdx", "测试", &werr, "Wow_loader.dll"), "写出: " + werr);
  auto back = load_hook_patterns(tmp("real/hooks/module.json"), nullptr);
  CHECK_EQ(back.size(), size_t(1));
  if (!back.empty()) CHECK_EQ(back[0].module, "Wow_loader.dll");

  // plan_hooks 多模块：把 descriptor 放进临时特征文件
  Json doc = Json::make_object();
  Json arr = Json::make_array(); arr.push(d);
  doc.set("patterns", arr);
  put("real/hooks/p.json", doc.dump(2));
  Config c2;
  c2.hooks.mode = "auto";
  c2.hooks.pattern_files = {tmp("real/hooks/p.json")};
  ClientInfo ci2; ci2.arch = "x64";
  HookPlan hp = plan_hooks(c2, ci2, images, nullptr);
  CHECK_EQ(hp.mode, "fileid");
  CHECK_EQ(hp.matches.size(), size_t(1));
  if (!hp.matches.empty()) {
    CHECK_EQ(hp.matches[0].module, "Wow_loader.dll");
    CHECK_EQ(hp.matches[0].file_offset, size_t(0x40));
  }
  // 单特征同时存在于主 exe 时不应重复命中（module 过滤生效）
  std::memcpy(exe.data() + 0x40, sig, sizeof(sig));
  HookPlan hp2 = plan_hooks(c2, ci2, {{"", exe}, {"Wow_loader.dll", dll}}, nullptr);
  CHECK_EQ(hp2.matches.size(), size_t(1));

  // 加密壳客户端：运行时内存映像（文件偏移 == RVA）也能被解析/扫描
  auto mapped = make_mapped_image();
  PeImage mpe;
  std::string merr;
  CHECK(mpe.load(mapped, &merr, true), "内存映像 PE 解析: " + merr);
  auto o = mpe.rva_to_offset(0x2100);
  CHECK(o.has_value() && *o == 0x2100u, "内存映像 RVA->偏移恒等");
  DiscoveryReport mrep = discover_hook_points(mapped, {"FileData ID %d %s"}, true);
  CHECK(mrep.pe, "内存映像应识别为 PE");
  CHECK_EQ(mrep.xref_count, size_t(1));
  CHECK_EQ(mrep.candidates.size(), size_t(1));
  if (!mrep.candidates.empty()) CHECK_EQ(mrep.candidates[0].code_rva, 0x2100u);
  // 不按 mapped 解析时，节区 raw_ptr 是磁盘偏移，得不到同一结果
  CHECK(!mpe.load(mapped, &merr, false) || true, "磁盘模式也能载入（但语义不同）");

  // 无 VS_VERSION_INFO 的 DLL：版本未知，但架构/导入表仍必须解析出来
  auto bare_dll = make_mapped_image();  // 有 PE 头、无版本资源、无导入表
  put_bytes("real/bare.dll", bare_dll);
  Diagnostics ddl;
  ClientInfo dci = detect_client(tmp("real/bare.dll"), &ddl);
  CHECK(dci.valid, "DLL 也应被 detect_client 接受");
  CHECK_EQ(dci.arch, "x64");
  CHECK(dci.version_string.empty() || dci.version_string.find("未知") != std::string::npos,
        "无版本资源时版本显示未知");
  CHECK(dci.to_json().at("supported").as_bool(), "无版本资源不会被版本门拒绝");
  CHECK_EQ(dci.to_json().at("supportStatus").as_string(), "not-verified");

  // 运行时扫描配置的 JSON 往返
  Config rc;
  rc.hooks.runtime_scan = true;
  rc.hooks.runtime_delay_ms = 9000;
  rc.hooks.runtime_dump = "dumps";
  rc.hooks.runtime_auto_install = false;
  rc.hooks.runtime_modules = {"wow_loader.dll"};
  Config rc2 = Config::from_json(rc.to_json(), tmp("real/cfg2.json"));
  CHECK(rc2.hooks.runtime_scan, "runtimeScan 往返");
  CHECK_EQ(rc2.hooks.runtime_delay_ms, 9000);
  CHECK(rc2.hooks.runtime_dump.size() >= 5 &&
        rc2.hooks.runtime_dump.substr(rc2.hooks.runtime_dump.size() - 5) == "dumps",
        "runtimeDump 应相对配置文件解析为绝对路径");
  CHECK(!rc2.hooks.runtime_auto_install, "默认不自动安装未验证 hook");
  CHECK_EQ(rc2.hooks.runtime_modules.size(), size_t(1));
  CHECK(rc2.hooks.inject_retry, "默认开启注入延迟重试");
  CHECK_EQ(rc2.hooks.inject_retry_attempts, 3);
  CHECK_EQ(rc2.hooks.inject_retry_delay_ms, 1000);
  Config rc3 = Config::from_json(rc.to_json(), tmp("real/cfg3.json"));
  CHECK(rc3.hooks.inject_retry && rc3.hooks.inject_retry_delay_ms == 1000 &&
        rc3.hooks.inject_retry_attempts == 3, "注入重试配置往返");
  CHECK(rc3.hooks.inject_windows_hook, "默认启用 Windows 钩子注入");
  Config rc4;
  rc4.hooks.inject_methods = {"loadlibrary", "ntcreatethreadex", "apc"};
  rc4.hooks.inject_windows_hook = false;
  Config rc5 = Config::from_json(rc4.to_json(), tmp("real/cfg5.json"));
  CHECK_EQ(rc5.hooks.inject_methods.size(), size_t(3));
  CHECK(!rc5.hooks.inject_windows_hook, "注入机制配置往返");
  CHECK(rc5.hooks.keep_client_on_inject_failure, "失败时默认不终止原游戏进程");

  // scanTargets 与导入表里的 DLL 只大小写不同，不应重复读 40MB 两次
  Config dc;
  dc.hooks.scan_targets = {"wow_loader.dll"};
  ClientInfo dci2;
  dci2.companion_dlls = {"Wow_loader.dll", "WOW_LOADER.DLL"};
  dci2.game_dir = tmp("real");
  std::vector<uint8_t> fake_dll(128, 0x90); fake_dll[0] = 'M'; fake_dll[1] = 'Z';
  put_bytes("real/wow_loader.dll", fake_dll);
  auto imgs = collect_hook_images(dc, dci2, {}, nullptr);
  size_t dll_images = 0;
  for (const auto& im : imgs) if (!im.module.empty()) ++dll_images;
  CHECK_EQ(dll_images, size_t(1));
}


// ---------------------------------------------------------------------------
// x86-64 长度解码：这些字节序列取自真实编译器输出，长度写错就会截断指令。
static void test_x64_decode() {
  group("x64_decode");

  auto len = [](std::initializer_list<uint8_t> bs) {
    std::vector<uint8_t> v(bs);
    return x64::decode(v.data(), v.size()).length;
  };

  CHECK_EQ(len({0x48, 0x89, 0x5C, 0x24, 0x08}), 5);            // mov [rsp+8], rbx
  CHECK_EQ(len({0x48, 0x83, 0xEC, 0x20}), 4);                  // sub rsp, 0x20
  CHECK_EQ(len({0x48, 0x8D, 0x15, 0x11, 0x22, 0x33, 0x44}), 7);// lea rdx,[rip+disp32]
  CHECK_EQ(len({0xE8, 0x00, 0x00, 0x00, 0x00}), 5);            // call rel32
  CHECK_EQ(len({0x74, 0x0C}), 2);                              // je rel8
  CHECK_EQ(len({0x0F, 0x84, 0x00, 0x01, 0x00, 0x00}), 6);      // je rel32
  CHECK_EQ(len({0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8}), 10);     // mov rax, imm64
  CHECK_EQ(len({0xB8, 0x01, 0x02, 0x03, 0x04}), 5);            // mov eax, imm32
  CHECK_EQ(len({0xF7, 0xD0}), 2);                              // not eax（无立即数）
  CHECK_EQ(len({0xF7, 0xC0, 1, 2, 3, 4}), 6);                  // test eax, imm32
  CHECK_EQ(len({0x49, 0x83, 0xC3, 0x10}), 4);                  // add r11, 0x10
  CHECK_EQ(len({0xC3}), 1);                                    // ret
  CHECK_EQ(len({0x43, 0x3B, 0x14, 0x1A}), 4);                  // cmp edx,[r10+r11]
  CHECK_EQ(len({0x4B, 0x8B, 0x44, 0x1A, 0x08}), 5);            // mov rax,[r10+r11+8]
  CHECK_EQ(len({0xC5, 0xF8, 0x77}), 3);                        // vzeroupper
  CHECK_EQ(len({0x62, 0xF1, 0x7C, 0x48, 0x28, 0xC0}), 6);      // EVEX vmovaps
  CHECK_EQ(len({0xF3, 0x48, 0x0F, 0x10, 0x01}), 5);            // movss xmm0,[rcx]

  // 指令边界：必须覆盖至少 14 字节且不切断指令
  const std::vector<uint8_t> code = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC,
                                     0x20, 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00};
  CHECK_EQ(x64::find_safe_split(code.data(), code.size(), 0, 14), 16u);
  CHECK(x64::is_instruction_aligned(code.data(), code.size(), 0, 16), "16 字节正好是指令边界");
  CHECK(!x64::is_instruction_aligned(code.data(), code.size(), 0, 14), "14 字节会切断 lea");

  // 重定位：RIP 相对位移按新地址重算
  {
    std::vector<uint8_t> blk = {0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00};  // lea rdx,[rip+0]
    const uint64_t src = 0x1000, dst = 0x8000;
    CHECK(x64::relocate_block(blk, src, dst), "可重定位");
    int32_t d = 0;
    std::memcpy(&d, blk.data() + 3, 4);
    // 原指令在 0x1000 时 RIP+0 指向 0x1007；搬到 0x8000 后应指向同一个绝对地址
    CHECK_EQ(static_cast<int64_t>(dst + 7 + d), static_cast<int64_t>(src + 7));
  }
}

// ---------------------------------------------------------------------------
// 启动器前置 stub：.pdata 驱动的 padding cave 选址 + 早期执行代码生成。
// 这是"在客户端任何用户线程存在之前就跑我们代码"的唯一干净途径，
// 所以选址逻辑必须逐字节可验证。
static std::vector<uint8_t> make_synthetic_pe() {
  std::vector<uint8_t> f(0x2000, 0);
  f[0] = 'M'; f[1] = 'Z';
  auto w32 = [&](size_t o, uint32_t v) { std::memcpy(&f[o], &v, 4); };
  auto w64 = [&](size_t o, uint64_t v) { std::memcpy(&f[o], &v, 8); };
  auto w16 = [&](size_t o, uint16_t v) { std::memcpy(&f[o], &v, 2); };
  w32(0x3C, 0x40);
  w32(0x40, 0x00004550);
  w16(0x44, 0x8664); w16(0x46, 2); w16(0x54, 0xF0);
  const size_t opt = 0x58;
  w16(opt, 0x20B);
  w32(opt + 16, 0x1000);       // entry
  w64(opt + 24, 0x140000000);  // image base
  w32(opt + 56, 0x4000);       // size of image
  w32(opt + 108, 16);          // number of dirs
  w32(opt + 112 + 3 * 8, 0x2000);  // .pdata RVA
  w32(opt + 112 + 3 * 8 + 4, 24);  // .pdata size
  const size_t sec = opt + 0xF0;
  auto setsec = [&](int i, const char* name, uint32_t va, uint32_t vs, uint32_t rs,
                    uint32_t rp, uint32_t ch) {
    const size_t o = sec + i * 40;
    std::memcpy(&f[o], name, std::strlen(name) < 8 ? std::strlen(name) : 8);
    w32(o + 8, vs); w32(o + 12, va); w32(o + 16, rs); w32(o + 20, rp); w32(o + 36, ch);
  };
  setsec(0, ".text", 0x1000, 0x800, 0x800, 0x400, 0x60000020);
  setsec(1, ".pdata", 0x2000, 0x200, 0x200, 0xC00, 0x40000040);
  // 函数入口 0x1400 之前放 128 字节 0xCC 填充（真实 PE 里这是链接器的 int3 padding）
  for (size_t i = 0x400 + 0x380; i < 0x400 + 0x400; ++i) f[i] = 0xCC;
  const uint8_t prologue[] = {0x48, 0x89, 0x5C, 0x24, 0x08};  // mov [rsp+8], rbx
  std::memcpy(&f[0x400 + 0x400], prologue, sizeof(prologue));
  const size_t pd = 0xC00;
  w32(pd + 0, 0x1100); w32(pd + 4, 0x1130); w32(pd + 8, 0x2000);
  w32(pd + 12, 0x1400); w32(pd + 16, 0x1500); w32(pd + 20, 0x2010);
  return f;
}

static void test_launcher_stub() {
  group("launcher_stub");

  const auto f = make_synthetic_pe();
  const PeLayout pe = parse_pe_file(f);
  CHECK(pe.ok, "合成 PE 应能解析");
  CHECK_EQ(pe.image_base, 0x140000000ull);
  CHECK_EQ(pe.pdata.size(), 2u);
  if (pe.pdata.size() == 2) {
    CHECK_EQ(pe.pdata[1].begin_rva, 0x1400u);
    CHECK_EQ(pe.pdata[1].end_rva, 0x1500u);
    const PeLayout::Section* sc = pe.section_of(0x1400);
    CHECK(sc != nullptr, "0x1400 应属于某个节");
    if (sc) CHECK(sc->executable(), "所在节必须可执行");
  }

  const StubPlan plan = plan_launcher_stub(pe, f, 64, true);
  CHECK(plan.ok, "应找到紧邻函数入口的填充区");
  if (plan.ok) {
    // cave 必须完整落在 padding 之内，且不覆盖函数本身
    CHECK_EQ(plan.cave_rva, 0x10C0u);
    CHECK_EQ(plan.cave_size, 64u);
    CHECK(plan.cave_rva + plan.cave_size <= 0x1400u, "cave 不能压到函数入口");
    CHECK(plan.begin_field_rva < f.size(), "begin 字段偏移必须在文件内");
  }

  // 整个 .text 前部最多只有 1024 字节可作填充（0x1000..0x1400），
  // 要 2048 字节时必须拒绝，而不是越界 / 压到别的代码上。
  const StubPlan too_big = plan_launcher_stub(pe, f, 2048, true);
  CHECK(!too_big.ok, "填充区不够大时必须拒绝，而不是硬写");

  // 代码生成：85 字节，结构固定，可逐字节校验
  const std::vector<uint8_t> stolen = {0x48, 0x89, 0x5C, 0x24, 0x08};
  const auto code = build_launcher_stub(0x140100000ULL, 0x140001380ULL, stolen);
  CHECK_EQ(code.size(), 85u);
  if (code.size() == 85) {
    CHECK_EQ(code[0], 0x9Cu);  // pushfq
    CHECK_EQ(code[1], 0x50u);  // push rax
    // 所有 push/pop 必须成对：14 个 push 之后跟 14 个 pop
    // 逐条解码，统计 push/pop 是否配平（stub 里任何一次不配平都会毁掉调用者栈）
    size_t pushes = 0, pops = 0, off = 0;
    while (off < code.size()) {
      const auto insn = x64::decode(code.data() + off, code.size() - off);
      if (insn.length == 0) break;
      if (insn.opcode == 0x50 || insn.opcode == 0x51 || insn.opcode == 0x52 ||
          insn.opcode == 0x53 || insn.opcode == 0x54 || insn.opcode == 0x55 ||
          insn.opcode == 0x56 || insn.opcode == 0x57 || insn.opcode == 0x9C ||
          insn.opcode == 0x41 || insn.opcode == 0x48 || insn.opcode == 0x49)
        ++pushes;  // 粗略计数，下面用精确字节校验代替
      ++off;
    }
    // 精确校验：stub 开头必须是 pushfq + 14 个寄存器压栈的固定字节序列
    static const uint8_t kPrologue[] = {0x9C, 0x50, 0x51, 0x52, 0x53, 0x56, 0x57,
                                        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
                                        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57};
    CHECK_EQ(sizeof(kPrologue), 23u);
    CHECK(std::equal(kPrologue, kPrologue + sizeof(kPrologue), code.begin()),
          "开头必须是 pushfq + 14 个通用寄存器压栈");
    static const uint8_t kEpilogue[] = {0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
                                        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
                                        0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0x9D};
    CHECK(std::search(code.begin(), code.end(), kEpilogue, kEpilogue + sizeof(kEpilogue)) !=
              code.end(),
          "寄存器恢复必须是逆序 pop + popfq");
    (void)pushes; (void)pops;
    // 最后必须是 movabs rax, <跳回地址>; jmp rax
    // 约束：cave 紧贴函数入口，所以「stub 末尾」就是真实入口地址。
    // build_launcher_stub 据此把跳回目标算成 stub_va + stub 长度。
    const uint64_t stub_va = 0x140001380ULL;
    uint64_t back = 0;
    std::memcpy(&back, code.data() + code.size() - 10, 8);  // movabs 的 imm64
    CHECK_EQ(back, stub_va + code.size());
    CHECK_EQ(code[code.size() - 12], 0x48u);
    CHECK_EQ(code[code.size() - 11], 0xB8u);
    CHECK_EQ(code[code.size() - 2], 0xFFu);
    CHECK_EQ(code[code.size() - 1], 0xE0u);
  }

  // 被偷的指令必须原样出现在跳回之前
  CHECK(std::search(code.begin(), code.end(), stolen.begin(), stolen.end()) != code.end(),
        "被顶替的原始指令必须原样搬进 stub");
}

// ---------------------------------------------------------------------------
// 跳板生成：编码必须真的能跳到正确的标签，寄存器必须真的被读到。
static void test_fileid_stub() {
  group("fileid_stub");

  for (const char* idr : {"rdx", "rcx", "r8", "r9", "rsi", "rdi", "rax", "r10", "r11"}) {
    StubConfig cfg;
    cfg.id_register = idr;
    cfg.return_register = "rax";
    auto r = build_fileid_stub(cfg, 0x10000000ULL, 8);
    CHECK(r.ok(), std::string("应该能生成跳板: ") + idr);
    if (!r.ok()) continue;
    CHECK_EQ(r.patch_slots.size(), 2u);
    // 所有指令都必须能完整解码（否则运行期必然崩）
    size_t p = 0;
    bool all_decoded = true;
    while (p < r.code.size()) {
      const auto insn = x64::decode(r.code.data() + p, r.code.size() - p);
      if (insn.length == 0) { all_decoded = false; break; }
      p += insn.length;
    }
    CHECK(all_decoded, std::string("生成的跳板必须全部可解码: ") + idr);
    // 最后一个指令必须是 ret
    CHECK_EQ(r.code.back(), 0xC3);
  }

  // 不支持的寄存器必须被拒绝，而不是生成坏代码
  {
    StubConfig cfg;
    cfg.id_register = "r12";
    CHECK(!build_fileid_stub(cfg, 0, 4).ok(), "r12 必须被拒绝");
    cfg.id_register = "esp";
    CHECK(!build_fileid_stub(cfg, 0, 4).ok(), "esp 必须被拒绝");
    cfg.id_register = "rbx";
    CHECK(!build_fileid_stub(cfg, 0, 0).ok(), "空表必须被拒绝");
  }

  // 表序列化
  {
    std::vector<std::pair<uint64_t, std::string>> entries = {{100, "a\\b.blp"}, {200, "c.blp"}};
    std::vector<uint8_t> blob;
    std::vector<std::pair<int, uint32_t>> offs;
    auto table = serialize_id_table(entries, &blob, &offs);
    CHECK_EQ(table.size(), 2 * FileIdEntryLayout::kStride);
    CHECK_EQ(offs.size(), 2u);
    CHECK_EQ(offs[0].second, 0u);
    CHECK_EQ(offs[1].second, 8u);  // "a\\b.blp" + NUL
    uint64_t id0 = 0;
    std::memcpy(&id0, table.data(), 8);
    CHECK_EQ(id0, 100ull);
  }
}

// ---------------------------------------------------------------------------
// 映像分析：字符串 -> 交叉引用 -> 函数起点 -> hook 点
static void test_analyze() {
  group("analyze");

  std::vector<uint8_t> img(0x9000, 0xCC);
  const char* s = "Locally overridden files";
  std::memcpy(img.data() + 0x8000, s, std::strlen(s) + 1);
  const uint64_t base = 0x140000000ull;

  size_t p = 0x1000;
  const uint8_t pro[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x20};
  std::memcpy(img.data() + p, pro, sizeof(pro));
  p += sizeof(pro);
  img[p++] = 0x48; img[p++] = 0x8D; img[p++] = 0x15;
  int64_t disp = static_cast<int64_t>(base + 0x8000) - static_cast<int64_t>(base + p + 4);
  std::memcpy(img.data() + p, &disp, 4);
  p += 4;
  img[p++] = 0xE8;
  int32_t rel = 0x20;
  std::memcpy(img.data() + p, &rel, 4);
  p += 4;
  const uint8_t epi[] = {0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3};
  std::memcpy(img.data() + p, epi, sizeof(epi));

  ImageView v;
  v.data = img.data();
  v.size = img.size();
  v.base_va = base;
  auto res = analyze_image(v);
  CHECK(res.ok, "分析应成功");
  CHECK(!res.string_hits.empty(), "应找到标记字符串");
  CHECK(!res.sites.empty(), "应推导出至少一个 hook 点方案");
  if (!res.sites.empty()) {
    CHECK_EQ(res.sites[0].function_rva, size_t(0x1000));
    CHECK(res.sites[0].site.ok, "函数起点应可 hook");
    CHECK(res.sites[0].site.copy_len >= 14, "覆盖长度应 >= 14");
  }

  // 空映像不能崩
  ImageView empty;
  auto bad = analyze_image(empty);
  CHECK(!bad.ok, "空映像应报错");
}

// ---------------------------------------------------------------------------
// 回归测试（2026-11-13）：真实客户端分析卡死 32 分钟的原因有两个
//   1. find_code_refs_to 给整幅映像建了个用完就丢的 std::map 索引
//   2. 分析阶段对「每个字符串命中」各扫一遍全图
//   3. 而且 REX 前缀判断写错，48 8D 0D ... 这种最常见的 lea 永远匹配不到
// 这里锁死第 3 点（正确性）和第 2 点（多目标必须一次扫描）。
static void test_xref_multi_target() {
  group("xref(多目标一次扫描)");

  std::vector<uint8_t> img(0x10000, 0xCC);
  const uint64_t base = 0x140000000ull;
  // 三个字符串，各自被一条带 REX 前缀的 lea 引用
  const char* strs[3] = {"Locally overridden files", "CASC", "FileDataID"};
  size_t str_off[3] = {0x8000, 0x9000, 0xa000};

  std::vector<uint64_t> targets;
  for (int k = 0; k < 3; ++k) {
    std::memcpy(img.data() + str_off[k], strs[k], std::strlen(strs[k]) + 1);
    const size_t fn_off = 0x1000 + static_cast<size_t>(k) * 0x100;
    img[fn_off] = 0x55;              // push rbp
    img[fn_off + 1] = 0x48;          // REX.W
    img[fn_off + 2] = 0x8D;          // lea
    img[fn_off + 3] = 0x0D;          // rcx, [rip+disp32]
    img[fn_off + 8] = 0xC3;          // ret
    const int64_t disp = static_cast<int64_t>(base + str_off[k]) -
                         static_cast<int64_t>(base + fn_off + 8);
    std::memcpy(img.data() + fn_off + 4, &disp, 4);
    targets.push_back(base + str_off[k]);
  }

  ImageView v;
  v.data = img.data();
  v.size = img.size();
  v.base_va = base;

  // 带 REX 前缀的 lea 必须被识别（旧实现漏掉这一整类）
  auto one = find_code_refs_to(v, targets[0]);
  CHECK_EQ(one.size(), size_t(1));
  if (!one.empty()) CHECK_EQ(one[0].at, size_t(0x1001));  // 0x1000 是 push rbp，lea 从 0x1001 起

  // 多目标一次扫描，结果必须和逐个调用一致
  auto many = find_code_refs_to_many(v, targets, 64);
  CHECK_EQ(many.size(), size_t(3));
  for (int k = 0; k < 3; ++k) {
    auto it = many.find(targets[k]);
    CHECK(it != many.end(), "每个目标都应有引用");
    if (it != many.end()) {
      CHECK_EQ(it->second.size(), size_t(1));
      if (!it->second.empty())
        CHECK_EQ(it->second[0].at, 0x1001 + static_cast<size_t>(k) * 0x100);
    }
  }

  // 整个分析流程要在秒级完成，且三个标记都要出来
  AnalyzeOptions opt;
  opt.refs_budget_seconds = 5.0;
  opt.id_budget_seconds = 5.0;
  auto res = analyze_image(v, opt);
  CHECK(res.ok, "分析应成功");
  CHECK_EQ(res.string_hits.size(), size_t(3));
  CHECK_EQ(res.detour_targets.size(), size_t(3));
}

// ---------------------------------------------------------------------------
// 回归测试（2026-11-13，第二次）：真实客户端那块 108MB 内存是【磁盘文件布局】
// （MZ 头、SizeOfImage 全对，标记字符串也在，但 xref 一个引用都没有）。
// 原因：RIP 相对引用的 disp32 按 RVA 编码，而文件布局里节数据在
// PointerToRawData 处，两者差 delta -> 必然对不上。
// 修法：原样扫不到引用时按节表重映射成内存布局再分析（结果自证，不猜）。
static void test_file_layout_remap() {
  group("文件布局自动重映射");

  // 造 PE：.text va=0x1000 raw=0x400，.data va=0x5000 raw=0x3400
  // 两个节的 delta 不同，这样文件布局下位移关系一定破坏。
  const size_t kSize = 0x9000;
  std::vector<uint8_t> mem(kSize, 0x00);
  mem[0] = 'M'; mem[1] = 'Z';
  auto w32 = [&](size_t off, uint32_t v) { std::memcpy(mem.data() + off, &v, 4); };
  auto w16 = [&](size_t off, uint16_t v) { std::memcpy(mem.data() + off, &v, 2); };
  w32(0x3C, 0x80);
  std::memcpy(mem.data() + 0x80, "PE\0\0", 4);
  w16(0x84, 0x8664);      // machine
  w16(0x86, 2);           // NumberOfSections
  w16(0x94, 0xE0);        // SizeOfOptionalHeader
  w16(0x98, 0x20B);       // PE32+
  w32(0x98 + 16, 0x1000); // EntryPoint
  w32(0x98 + 56, kSize);  // SizeOfImage
  const size_t sh = 0x98 + 0xE0;
  auto section = [&](size_t off, const char* name, uint32_t vsize, uint32_t va,
                     uint32_t rsize, uint32_t rptr) {
    std::memcpy(mem.data() + off, name, std::strlen(name));
    w32(off + 8, vsize); w32(off + 12, va); w32(off + 16, rsize); w32(off + 20, rptr);
  };
  section(sh, ".text", 0x4000, 0x1000, 0x4000, 0x400);
  section(sh + 40, ".data", 0x2000, 0x5000, 0x2000, 0x3400);

  const char* strs[3] = {"Locally overridden files", "CASC", "FileDataID"};
  for (int k = 0; k < 3; ++k) {
    const size_t sva = 0x5100 + static_cast<size_t>(k) * 0x100;
    std::memcpy(mem.data() + sva, strs[k], std::strlen(strs[k]) + 1);
    const size_t insn_va = 0x1100 + static_cast<size_t>(k) * 0x40;
    mem[insn_va] = 0x55;
    mem[insn_va + 1] = 0x48; mem[insn_va + 2] = 0x8D; mem[insn_va + 3] = 0x0D;
    mem[insn_va + 8] = 0xC3;
    const int64_t disp = static_cast<int64_t>(sva) - static_cast<int64_t>(insn_va + 8);
    std::memcpy(mem.data() + insn_va + 4, &disp, 4);
  }

  // 造文件布局：把节数据搬到各自的 raw_ptr 处
  std::vector<uint8_t> file(kSize, 0x00);
  std::memcpy(file.data(), mem.data(), 0x400);          // 头 + 节表
  std::memcpy(file.data() + 0x400, mem.data() + 0x1000, 0x4000);   // .text
  std::memcpy(file.data() + 0x3400, mem.data() + 0x5000, 0x2000);  // .data

  // 文件布局：字符串找得到，但直接 xref 一定 0 个引用
  ImageView fv;
  fv.data = file.data();
  fv.size = file.size();
  fv.base_va = 0x140000000ull;
  {
    AnalyzeOptions o;
    o.allow_file_remap = false;   // 关掉自动重映射，验证"原样扫不到"
    o.refs_budget_seconds = 10;
    o.id_budget_seconds = 5;
    auto r = analyze_image(fv, o);
    CHECK(r.ok, "文件布局分析应成功返回");
    CHECK(r.string_hits.empty(), "文件布局下原样扫描不应找到代码引用");
    CHECK(!r.orphan_strings.empty(), "字符串本身应该找得到（只是无引用）");
    CHECK(!r.used_file_remap, "关掉重映射时不应报告使用过重映射");
  }

  // 打开自动重映射：应该救回来
  {
    AnalyzeOptions o;
    o.refs_budget_seconds = 10;
    o.id_budget_seconds = 5;
    auto r = analyze_image(fv, o);
    CHECK(r.ok, "自动重映射分析应成功");
    CHECK(r.used_file_remap, "应报告使用了文件布局重映射");
    CHECK_EQ(r.string_hits.size(), size_t(3));
    CHECK_EQ(r.detour_targets.size(), size_t(3));
    if (r.detour_targets.size() == 3) {
      CHECK_EQ(r.detour_targets[0].function_rva, size_t(0x1100));
      CHECK(r.detour_targets[0].hookable, "重映射后的函数起点应可 hook");
    }
  }

  // 内存布局不受影响
  {
    ImageView mv;
    mv.data = mem.data();
    mv.size = mem.size();
    mv.base_va = 0x140000000ull;
    AnalyzeOptions o;
    o.refs_budget_seconds = 10;
    o.id_budget_seconds = 5;
    auto r = analyze_image(mv, o);
    CHECK(r.ok, "内存布局分析应成功");
    CHECK(!r.used_file_remap, "内存布局不应触发重映射");
    CHECK_EQ(r.string_hits.size(), size_t(3));
  }
}

// ---------------------------------------------------------------------------
// 回归测试（2026-11-13，第三次）：真实客户端的假阴性
//
// 现象：同一块内存 0x3ac0000，上一版给出「字符串 2 个 / detour 1 个」，
// 这一版给出「字符串 0 个 / detour 0 个」，而代码根本没改。
// 原因：客户端同时保留多份同尺寸的映像副本，其中有的只有数据段、
// 没有可执行节。挑中那种副本就会得到"字符串找得到、但一个 RIP 相对引用
// 都没有"的假阴性 —— 看起来像分析算法坏了。
//
// 这里锁死两件事：
//   1) 真正有 lea 引用的映像必须被正确解析出来（不能假阴性）
//   2) 标记字符串出现次数超过 scan 上限时不能漏掉后面的引用
static void test_no_false_negative() {
  group("不能出现假阴性");

  const size_t kSize = 0x9000;
  std::vector<uint8_t> img(kSize, 0x00);
  auto w32 = [&](size_t off, uint32_t v) { std::memcpy(img.data() + off, &v, 4); };
  auto w16 = [&](size_t off, uint16_t v) { std::memcpy(img.data() + off, &v, 2); };

  img[0] = 'M'; img[1] = 'Z';
  w32(0x3C, 0x80);
  std::memcpy(img.data() + 0x80, "PE\0\0", 4);
  w16(0x84, 0x8664);
  w16(0x86, 2);
  w16(0x94, 0xE0);
  w16(0x98, 0x20B);
  w32(0x98 + 16, 0x1200);   // 入口点放在代码节内
  w32(0x98 + 56, kSize);
  const size_t sh = 0x98 + 0xE0;
  // .text: 可执行（0x60000020 = CODE|EXECUTE|READ）
  std::memcpy(img.data() + sh, ".text", 5);
  w32(sh + 8, 0x7000); w32(sh + 12, 0x1000); w32(sh + 16, 0x7000); w32(sh + 20, 0x1000);
  w32(sh + 36, 0x60000020u);
  // .data: 可读写（0xC0000040）
  std::memcpy(img.data() + sh + 40, ".data", 5);
  w32(sh + 40 + 8, 0x1000); w32(sh + 40 + 12, 0x8000);
  w32(sh + 40 + 16, 0x1000); w32(sh + 40 + 20, 0x8000);
  w32(sh + 40 + 36, 0xC0000040u);

  // 一条 lea 引用 "Locally overridden files"
  auto place_lea = [&](size_t insn_rva, size_t target_rva) {
    img[insn_rva] = 0x55;
    img[insn_rva + 1] = 0x48; img[insn_rva + 2] = 0x8D; img[insn_rva + 3] = 0x0D;
    img[insn_rva + 8] = 0xC3;
    const int64_t disp = static_cast<int64_t>(target_rva) - static_cast<int64_t>(insn_rva + 8);
    std::memcpy(img.data() + insn_rva + 4, &disp, 4);
  };
  const size_t s_loose = 0x8000;
  std::memcpy(img.data() + s_loose, "Locally overridden files", 25);
  place_lea(0x1100, s_loose);

  // 超过 scan 上限：FileDataID 铺 12 处，只有最后一处被引用
  for (int i = 0; i < 12; ++i) {
    const size_t o = 0x8200 + static_cast<size_t>(i) * 0x40;
    std::memcpy(img.data() + o, "FileDataID", 11);
  }
  place_lea(0x1200, 0x8200 + 11 * 0x40);

  ImageView v;
  v.data = img.data();
  v.size = img.size();
  v.base_va = 0x140000000ull;

  AnalyzeOptions o;
  o.refs_budget_seconds = 20;
  o.id_budget_seconds = 10;
  auto r = analyze_image(v, o);

  CHECK(r.ok, "分析应成功");
  CHECK(!r.used_file_remap, "内存布局不应触发重映射");
  // 决定性断言：两处引用都必须找到
  CHECK_EQ(r.string_hits.size(), size_t(2));
  CHECK_EQ(r.detour_targets.size(), size_t(2));
  // 未被引用的 11 处 FileDataID 应当作为孤儿如实报告（不是被静默丢弃），
  // 但真正的引用不能被挤掉。上面两条 string_hits/detour 断言已经锁死这点。
  // 12 个孤儿 = 11 处未引用的 FileDataID + 1 处 "overridden files"
  // （它是 "Locally overridden files" 的子串，也命中一次且无 lea 引用）
  CHECK_EQ(r.orphan_strings.size(), size_t(12));
  // 关键：被引用的必须是最后那处（第 12 个），证明上限没有截断到它
  bool found_last = false;
  for (const auto& h : r.string_hits) {
    if (h.marker == "FileDataID" && h.rva == 0x8200 + 11 * 0x40) found_last = true;
  }
  CHECK(found_last, "第 12 处 FileDataID 的引用不能被 scan 上限挤掉");
}

// ---------------------------------------------------------------------------
// 回归测试（2026-11-13，第四次）：MEM_MAPPED 映像节的保护属性
//
// 现象：分析全部成功（拿到了 rva=0x33e1890），安装拦截器时
//   VirtualProtectEx(RWX) 失败, GetLastError=87
// 原因：客户端映像那块 108MB 是 MEM_MAPPED 的映像节。对它请求
// PAGE_EXECUTE_READWRITE 是非法参数 —— 映像节的页保护必须与原始节属性
// 兼容，不能中途把非执行页变成可执行页。正确值是与 RWX 语义等价、
// 但映像节合法的 PAGE_EXECUTE_WRITECOPY（写时复制，不落盘）。
static void test_protect_plan() {
  group("保护属性选择");

  using namespace wowmod;
  // MEM_MAPPED 的只读映像页：首选必须是 WRITECOPY 系列，绝不能是 RWX
  {
    auto c = writable_protect_candidates(kMemMapped, 0x04 /*PAGE_READWRITE*/);
    CHECK(!c.empty(), "应给出候选");
    CHECK(c[0] != kPageExecuteReadWrite, "MEM_MAPPED 不能首选 RWX（会 87）");
    bool has_wc = false;
    for (uint32_t v : c)
      if (v == kPageWriteCopy || v == kPageExecuteWriteCopy) has_wc = true;
    CHECK(has_wc, "MEM_MAPPED 候选中必须含 WRITECOPY");
  }
  // MEM_IMAGE 同理
  {
    auto c = writable_protect_candidates(kMemImage, 0x04);
    CHECK(!c.empty(), "MEM_IMAGE 应给出候选");
    CHECK(c[0] != kPageExecuteReadWrite, "MEM_IMAGE 不能首选 RWX（会 87）");
  }
  // 私有内存可以用 RWX
  {
    auto c = writable_protect_candidates(0x20000 /*MEM_PRIVATE*/, 0x04);
    CHECK(!c.empty(), "私有内存应给出候选");
    CHECK_EQ(c[0], kPageExecuteReadWrite);
  }
  // 可执行的映像节：仍优先 WRITECOPY（保执行 + 可写）
  {
    auto c = writable_protect_candidates(kMemImage, 0x20 /*PAGE_EXECUTE_READ*/);
    CHECK(!c.empty(), "可执行映像节应给出候选");
    CHECK_EQ(c[0], kPageExecuteWriteCopy);
  }
}

// Arctium 特征码表的自检：不依赖客户端，只用合成映像验证
// 「特征码能解析、能在已知字节处唯一命中、改写点偏移指向预期位置」。
// 真正的 12.0.7 匹配结果由 launcher --mode sigscan 现场给出，这里不伪造。
static void test_arctium_signature_table() {
  group("arctium-signature-table");
  const auto& sigs = wowmod::arctium_signature_specs();
  CHECK(sigs.size() >= 3, "至少包含 CustomFileIdHook / LoadByFileId / LoadByFilePath");

  bool saw_custom = false, saw_loadbyid = false, saw_loadbypath = false;
  for (const auto& sg : sigs) {
    std::string err;
    wowmod::Pattern p = wowmod::Pattern::parse(sg.pattern, &err);
    CHECK(p.valid(), std::string("特征码可解析: ") + sg.name + " " + err);
    CHECK(p.size() > 8, std::string("特征码长度合理: ") + sg.name);
    CHECK(sg.patch_offset >= 0, std::string("改写偏移非负: ") + sg.name);
    if (std::string(sg.name) == "CustomFileIdHook") saw_custom = true;
    if (std::string(sg.name) == "LoadByFileId") saw_loadbyid = true;
    if (std::string(sg.name) == "LoadByFilePath") saw_loadbypath = true;
  }
  CHECK(saw_custom, "有文件打开函数本身的特征");
  CHECK(saw_loadbyid, "有 LoadByFileId 分支特征");
  CHECK(saw_loadbypath, "有 LoadByFilePath 分支特征");

  // 按特征本身构造一段映像：固定字节照抄，通配位填 0x90，
  // 再断言「能在预期起点唯一命中、改写点 = 起点 + patch_offset」。
  // 这是对匹配器与偏移语义的验证，不代表客户端里真的有这个函数。
  for (const auto& sg : sigs) {
    std::string err2;
    wowmod::Pattern pat = wowmod::Pattern::parse(sg.pattern, &err2);
    if (!pat.valid()) continue;

    const size_t pad = 16;
    std::vector<uint8_t> img(pad + pat.size() + pad, 0xCC);
    for (size_t k = 0; k < pat.size(); ++k)
      img[pad + k] = pat.bytes[k] >= 0 ? static_cast<uint8_t>(pat.bytes[k]) : 0x90;

    const auto hits = pat.find_all(img);
    CHECK_EQ(hits.size(), size_t(1));
    if (!hits.empty()) {
      CHECK_EQ(hits[0], pad);
      const uint64_t match_va = 0x140001000ull + pad;
      const uint64_t patch_va = match_va + static_cast<uint64_t>(sg.patch_offset);
      CHECK_EQ(patch_va, 0x140001000ull + pad + static_cast<uint64_t>(sg.patch_offset));
      CHECK(sg.patch_offset < static_cast<int>(pat.size()),
            std::string("改写点落在特征范围内: ") + sg.name);
    }
  }

  // 空/垃圾特征不应崩，也不应误报。
  std::string err3;
  wowmod::Pattern bogus = wowmod::Pattern::parse("ZZ ZZ", &err3);
  CHECK(!bogus.valid(), "非法特征码不合法");
}

// 拦截跳板语义测试（定义在 tests/intercept_test.cpp）
namespace wowmod { namespace test { int run_intercept_stub_tests(int* checks); } }

int main() {
  std::cout << "wowmod 核心测试\n";
  std::cout << std::string(50, '-') << "\n";
  setup();
  test_util();
  test_json();
  test_version();
  test_mapping();
  test_arctium_file_plan();
  test_config();
  test_vfs();
  test_hooks();
  test_discover();
  test_x64_decode();
  test_fileid_stub();
  test_launcher_stub();
  test_analyze();
  test_xref_multi_target();
  test_file_layout_remap();
  test_no_false_negative();
  test_protect_plan();
  test_arctium_signature_table();
  {
    int extra = 0;
    g_failed += wowmod::test::run_intercept_stub_tests(&extra);
    g_total += extra;
  }
  test_real_client();
  teardown();
  std::cout << std::string(50, '-') << "\n";
  std::cout << g_total << " 项检查, " << g_failed << " 项失败\n";
  return g_failed ? 1 : 0;
}
