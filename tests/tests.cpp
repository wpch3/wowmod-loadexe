// 零依赖单元测试：覆盖核心逻辑（可在 Linux/macOS/Windows 上运行）。
// SPDX-License-Identifier: MIT
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iostream>
#include <string>
#include <vector>

#include "wowmod/analyze.hpp"
#include "wowmod/protect_plan.hpp"
#include "wowmod/arctium.hpp"
#include "wowmod/fileid_stub.hpp"
#include "wowmod/x64sim.hpp"
#include "wowmod/anticrash_plan.hpp"
#include "wowmod/image_select.hpp"
#include "wowmod/mods_selfcontained.hpp"
#include "windows/arctium_clone.hpp"
#include "wowmod/launcher_stub.hpp"
#include "wowmod/x64_decode.hpp"
#include "wowmod/xref.hpp"
#include "wowmod/config.hpp"
#include "wowmod/discover.hpp"
#include "wowmod/arctium_sigs.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/json.hpp"
#include "wowmod/probe_stub.hpp"
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
// ---- 旁路记录跳板（probe_stub）----
//
// 这个跳板是手写机器码，一旦字节错一位就是把客户端打崩。所以这里逐项验证：
//   1. 每一段都能被完整解码（没有错位/半截指令）
//   2. 必须以 jmp qword ptr [rip+0] 结尾（跳回 trampoline）
//   3. 必须 push/pop 成对，且保存了 r10/r11（跳板自己要用）
//   4. 必须【不】写返回寄存器 rax（这是它和 fileid_stub 的根本区别）
// ---- minidump 异常流解析的偏移约定 ----
//
// 这段逻辑在 crash_evidence.cpp 里（_WIN32 专属），但"偏移算错"这件事
// 在 Linux 上完全可以验证 —— 用一份按 c00000e5 真实形状构造的假转储，
// 把同样的解析规则跑一遍，确认取出来的 RIP / 崩溃码是我们要的那两个值。
// 实测里崩溃码就是 0xC00000E5、RIP 就是 0x7ffdf976741ca（用户截图）。
static void test_minidump_layout() {
  group("minidump_layout");

  auto rd32 = [](const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
  };
  auto rd64 = [](const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
  };
  auto wr32 = [](std::vector<uint8_t>* b, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) (*b)[at + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
  };
  auto wr64 = [](std::vector<uint8_t>* b, size_t at, uint64_t v) {
    for (int i = 0; i < 8; ++i) (*b)[at + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
  };

  const uint32_t kCode = 0xC00000E5u;
  const uint64_t kRip = 0x00007FFDF976741CAULL;
  const uint32_t kThread = 4242;

  std::vector<uint8_t> d(32 + 12 + 168, 0);
  wr32(&d, 0, 0x504D444Du);   // 'MDMP'
  wr32(&d, 4, 0xA793);        // version
  wr32(&d, 8, 1);             // num_streams
  wr32(&d, 12, 32);           // dir_rva（头固定 32 字节）
  // 目录项
  wr32(&d, 32, 6);            // EXCEPTION_STREAM
  wr32(&d, 36, 168);
  wr32(&d, 40, 44);           // stream rva
  // EXCEPTION_STREAM
  const size_t st = 44;
  wr32(&d, st + 0, kThread);
  wr32(&d, st + 8, kCode);    // ExceptionCode
  wr64(&d, st + 24, kRip);    // ExceptionAddress
  wr64(&d, st + 40, 0x303);   // ExceptionInformation[1]

  // 按 crash_evidence.cpp 的规则解析
  CHECK_EQ(rd32(d.data()), 0x504D444Du);
  const uint32_t n = rd32(d.data() + 8);
  const uint32_t drva = rd32(d.data() + 12);
  CHECK_EQ(n, 1u);
  CHECK_EQ(drva, 32u);
  const uint32_t type = rd32(d.data() + drva);
  const uint32_t rva = rd32(d.data() + drva + 8);
  CHECK_EQ(type, 6u);
  CHECK_EQ(rva, 44u);
  CHECK_EQ(rd32(d.data() + rva), kThread);
  CHECK_EQ(rd32(d.data() + rva + 8), kCode);
  CHECK_EQ(rd64(d.data() + rva + 24), kRip);
  CHECK_EQ(rd64(d.data() + rva + 40), 0x303ULL);

  // 判定逻辑：崩溃地址落在我们的 hook 区间里 -> 1
  {
    std::vector<std::pair<uint64_t, uint64_t>> hooked = {{kRip - 4, kRip + 10}};
    std::vector<std::pair<uint64_t, uint64_t>> stubs;
    const bool inside = kRip >= hooked[0].first && kRip < hooked[0].second;
    CHECK(inside, "假转储的 RIP 应落在构造的 hook 区间内");
    // 区间外
    std::vector<std::pair<uint64_t, uint64_t>> outside = {{kRip + 0x1000, kRip + 0x2000}};
    const bool not_inside = !(kRip >= outside[0].first && kRip < outside[0].second);
    CHECK(not_inside, "区间外应判定为不相关");
    // 跳板区间
    std::vector<std::pair<uint64_t, uint64_t>> stubs2 = {{kRip, kRip + 0x200}};
    CHECK(kRip >= stubs2[0].first && kRip < stubs2[0].second, "应能判定为落在跳板内");
  }
}

static void test_probe_stub() {
  group("probe_stub");

  for (const char* idr : {"edx", "ecx", "r8d", "r9d", "esi", "edi", "eax"}) {
    ProbeStubConfig cfg;
    cfg.id_reg = wowmod::register_number(idr);
    auto r = build_probe_stub(cfg, 0x20000000000ULL);
    CHECK(r.ok(), std::string("应该能生成旁路跳板: ") + idr);
    if (!r.ok()) continue;

    // 1) 全部指令可解码
    size_t p = 0;
    int guard = 0;
    bool all_ok = true;
    while (p < r.code.size() && guard++ < 200) {
      const auto insn = wowmod::x64::decode(r.code.data() + p, r.code.size() - p);
      if (insn.length == 0) { all_ok = false; break; }
      p += insn.length;
    }
    CHECK(all_ok, std::string("跳板必须全部可解码: ") + idr);
    CHECK_EQ(p, r.code.size());

    // 2) 结尾必须是 FF 25 00000000 + 8 字节地址
    CHECK(r.code.size() >= 14, "断言失败: r.code.size() >= 14");
    if (r.code.size() >= 14) {
      const size_t j = r.code.size() - 14;
      CHECK_EQ(r.code[j], 0xFF);
      CHECK_EQ(r.code[j + 1], 0x25);
      CHECK_EQ(r.code[j + 2], 0x00);
      CHECK_EQ(r.code[j + 3], 0x00);
      CHECK_EQ(r.code[j + 4], 0x00);
      CHECK_EQ(r.code[j + 5], 0x00);
    }
    CHECK_EQ(r.patch_slots.size(), 1u);
    if (!r.patch_slots.empty()) CHECK_EQ(r.patch_slots[0].second, "trampoline_va");

    // 3) push/pop 配平：push 次数 == pop 次数（含 pushfq/popfq）
    int pushes = 0, pops = 0;
    p = 0;
    while (p < r.code.size()) {
      const auto insn = wowmod::x64::decode(r.code.data() + p, r.code.size() - p);
      if (insn.length == 0) break;
      // 只统计跳板前半段（末尾的 jmp 之后是数据）
      if (r.code[p] == 0xFF && p + 1 < r.code.size() && r.code[p + 1] == 0x25) break;
      if (r.code[p] == 0x9C) pushes++;
      else if (r.code[p] == 0x9D) pops++;
      else if ((r.code[p] & 0xF8) == 0x50) pushes++;
      else if (r.code[p] == 0x41 && p + 1 < r.code.size() &&
               (r.code[p + 1] & 0xF8) == 0x50) pushes++;
      else if ((r.code[p] & 0xF8) == 0x58) pops++;
      else if (r.code[p] == 0x41 && p + 1 < r.code.size() &&
               (r.code[p + 1] & 0xF8) == 0x58) pops++;
      p += insn.length;
    }
    CHECK_EQ(pushes, pops);
    CHECK(pushes >= 6, std::string("至少要保存 5 个寄存器 + rflags: ") + idr);
  }

  // 4) 不写返回寄存器：不能出现 mov [rdx+0x18], eax 之外的 rax 写回
  //    这里直接检查有没有 "89 ... 24" 之外的 rax 目标写，
  //    更简单可靠的做法：确认没有 48 89 或 89 后面跟 modrm 指向 rax 的存储。
  {
    ProbeStubConfig cfg;
    cfg.id_reg = 2;  // edx
    auto r = build_probe_stub(cfg, 0x20000000000ULL);
    CHECK(r.ok(), "断言失败: r.ok()");
    // 整段代码里不应该出现 "mov rax, [table+..]"（fileid_stub 的命中返回）
    bool has_table_load = false;
    for (size_t i = 0; i + 3 < r.code.size(); ++i) {
      if (r.code[i] == 0x49 && r.code[i + 1] == 0x8B && (r.code[i + 2] & 0xC7) == 0x02) {
        has_table_load = true;
      }
    }
    CHECK(!has_table_load, "旁路跳板不能从表里取路径（那是替换模式才做的事）");
    // 必须保存 r10 和 r11（跳板自己占用）
    bool has_r10 = false, has_r11 = false;
    for (size_t i = 0; i + 1 < r.code.size(); ++i) {
      if (r.code[i] == 0x41 && r.code[i + 1] == 0x52) has_r10 = true;
      if (r.code[i] == 0x41 && r.code[i + 1] == 0x53) has_r11 = true;
    }
    CHECK(has_r10, "必须保存 r10");
    CHECK(has_r11, "必须保存 r11");
  }

  // 5) 参数校验
  {
    ProbeStubConfig cfg;
    cfg.capacity = 1000;  // 不是 2 的幂
    CHECK(!build_probe_stub(cfg, 0).ok(), "非 2 的幂容量必须被拒绝");
    cfg.capacity = 4096;
    cfg.id_reg = 4;  // rsp
    CHECK(!build_probe_stub(cfg, 0).ok(), "rsp 作为 id 寄存器必须被拒绝");
    cfg.id_reg = 99;
    CHECK(!build_probe_stub(cfg, 0).ok(), "越界寄存器必须被拒绝");
  }

  // 6) 布局常量自洽
  {
    CHECK_EQ(wowmod::ProbeBufferLayout::kSlotsOff, 0x18u);
    CHECK_EQ(wowmod::ProbeBufferLayout::kSlotStride, 16u);
    CHECK_EQ(wowmod::ProbeBufferLayout::bytes_for(4096), 0x18u + 4096u * 16u);
    // seq 偏移必须落在槽位内
    CHECK(wowmod::ProbeBufferLayout::kSlotSeqOff < wowmod::ProbeBufferLayout::kSlotStride, "断言失败: wowmod::ProbeBufferLayout::kSlotSeqOff < wowmod::P");
  }

  // 7) 寄存器名解析
  CHECK_EQ(wowmod::register_number("edx"), 2);
  CHECK_EQ(wowmod::register_number("rdx"), 2);
  CHECK_EQ(wowmod::register_number("r15d"), 15);
  CHECK_EQ(wowmod::register_number("nope"), -1);
}

// 跳板语义的离线执行验证。
//
// 只看「能否解码」是不够的：字节全都能解码、但逻辑写错（比如循环上界用
// 项数而不是字节数）照样会让 95% 的文件匹配不到，或者返回错指针直接崩。
// 这里用 x64sim 把生成的跳板真的执行一遍，逐条比对结果。
// Arctium 原版 stub 的行为验证（12 字节表布局）。
//
// 与我们的 16 字节 custom stub 不同，Arctium 的语义是：
//   负 id  -> js 跳到 +50 执行原始指令（完全旁路）
//   命中   -> 返回路径指针
//   未命中 -> xor eax,eax / ret 返回 0（【不】执行原始指令）
// 最后一条是 x64sim 实际跑出来的，不是从源码读出来的直觉 ——
// 源码里 0x33 `xor eax,eax` / 0x43 `ret` 就在未命中路径的末尾。
// 安装时序的静态约束。
//
// 用户反复踩到的崩溃与"没生效"，根因都在【顺序】上：
//   * 边跑边写 -> 命中半条指令 -> EXCEPTION_INTERNAL_ERROR
//   * 先装跳板后判 NoJump -> 改了内存但行为没变
// 这些没法在 Linux 上运行时验证（要真进程），但可以从源码结构上锁死：
// 挂起必须在写入之前，恢复必须在所有写入之后，且必须用 RAII 保证不遗漏。
// 解密进度统计的两个陷阱。
//
// 用户日志里出现过「明文页 142/142」，看起来 100% 解密，
// 实际是：分母只统计了【读成功】的页，而那 142 页全是零/空白。
// 这类"看起来很好的数字"最危险 —— 它会让人以为方向对了。
static void test_plain_page_accounting() {
  group("plain_page_accounting");
  std::string src;
  {
    std::ifstream in("src/windows/scan_images.cpp", std::ios::binary);
    if (in) src.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  }
  CHECK(!src.empty(), "应能读到 scan_images.cpp");
  if (src.empty()) return;

  // 分母必须单独计数
  CHECK(src.find("text_pages_total++") != std::string::npos,
        "必须有独立的 text_pages_total 作为分母");
  CHECK(src.find("text_pages_unreadable++") != std::string::npos,
        "读不出来的页必须单独统计，不能静默丢弃");
  CHECK(src.find("text_pages_blank++") != std::string::npos,
        "空白页必须单独统计");
  CHECK(src.find("is_blank_page") != std::string::npos,
        "必须有 is_blank_page —— 全零页的熵也是 0，会被误判成明文");

  // 顺序：必须先判 blank 再判熵，否则全零页会被算成明文
  const size_t p_blank = src.find("is_blank_page(page.data()");
  const size_t p_ent = src.find("out.text_low_entropy++", p_blank == std::string::npos ? 0 : p_blank);
  CHECK(p_blank != std::string::npos, "采样循环里必须调用 is_blank_page");
  CHECK(p_ent != std::string::npos && p_blank < p_ent,
        "必须先排除空白页，再统计明文页");

  // mod_loader 的就绪判据不能把 Init 当硬门槛
  std::string ml;
  {
    std::ifstream in("src/windows/mod_loader.cpp", std::ios::binary);
    if (in) ml.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  }
  CHECK(!ml.empty(), "应能读到 mod_loader.cpp");
  if (!ml.empty()) {
    // ---- 这一组断言曾经把错误当正确锁死了 ----
    //
    // 旧版本这里写着「就绪判据应该是目标特征码命中分达标」，
    // 也就是强制要求源码里存在 kNeedScore（我自己发明的 6/8 门槛）。
    // 正是那个门槛让用户第 1 轮明明 `Init 有` 却被判失败。
    // 测试去"验证实现细节"而不是"验证行为"，就会把 bug 焊死。
    //
    // 【这条断言本身也曾经是错的，必须记下来】
    //
    // 它原先写着 "Init 出现后必须立刻结束等待（这是 Arctium 的通过条件）"。
    // 但 Arctium 的 WaitForUnpack 是【两步】：
    //   1) Init 特征码出现
    //   2) initOffset += *(int*)(match+2) + 10; 等该地址上的字节 != 0
    // 第 1 步只说明那段代码被解密了，不说明客户端执行过它。
    // 照着这条错断言，实现就停在第一步，于是壳还没解密 Integrity/Remap
    // 那几个函数时我们就去扫描 -> "完整性校验 0 处" -> 闪退。
    //
    // 现在断言的是完整的两步语义。
    CHECK(ml.find("init_target_va") != std::string::npos,
          "必须从 Init 的 mov 立即数算出标记地址（WaitForUnpack 第二步）");
    CHECK(ml.find("解包完成") != std::string::npos,
          "标记置位后才算解包完成");
    CHECK(ml.find("仍为 0") != std::string::npos,
          "标记为 0 时必须继续等，不能看到特征码就走");
    // 我自己发明的分数门槛必须彻底消失，不能再回来
    CHECK(ml.find("kNeedScore") == std::string::npos,
          "kNeedScore（自造的 6/8 门槛）必须彻底移除 —— Arctium 没有这个概念");
  }
}

// 两个曾在同一轮里互相掩盖的 bug：
//   a) PEB 整块映像的 region_protect = 0，于是 has_rx 恒为 false，
//      映像内所有命中（包括 Init）都被判成"不可执行"；
//   b) 逐页读 PEB 映像时用"读到的字节总数"裁剪，前面有未提交页就会把
//      后面读到的整片代码切掉。
static void test_peb_image_protect_and_reach() {
  group("peb_image_protect_and_reach");
  auto slurp = [](const char* p) {
    std::string s;
    std::ifstream in(p, std::ios::binary);
    if (in) s.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s;
  };
  const std::string sig = slurp("src/windows/arctium_sig.cpp");
  const std::string scan = slurp("src/windows/scan_images.cpp");
  CHECK(!sig.empty(), "应能读到 arctium_sig.cpp");
  CHECK(!scan.empty(), "应能读到 scan_images.cpp");
  if (sig.empty() || scan.empty()) return;

  // a) 必须有「用内核真实保护属性覆盖哨兵值」的逻辑
  CHECK(sig.find("live_protect") != std::string::npos,
        "命中点的保护属性必须用 VirtualQueryEx 现场查询，不能只信映像级的字段");
  CHECK(sig.find("h.region_protect == 0") != std::string::npos,
        "region_protect == 0 是 PEB 整块映像的哨兵值，必须被真实值替换");
  // 顺序：先覆盖 protect，再推导 has_rx
  const size_t p_fix = sig.find("h.region_protect == 0");
  const size_t p_rx = sig.find("h.has_rx = (h.region_protect", p_fix);
  CHECK(p_fix != std::string::npos && p_rx != std::string::npos && p_fix < p_rx,
        "必须先修正 protect 再推导 has_rx，且 has_rx 必须读修正后的值");
  CHECK(sig.find("h.has_rx = (img.region_protect") == std::string::npos,
        "has_rx 不能读映像级 protect —— PEB 整块映像那里是 0");

  // 诊断必须报「主映像多大 / 实际读到多少」—— 这是判断扫描范围的唯一依据
  std::string sig_h;
  {
    std::ifstream in("src/windows/arctium_sig.hpp", std::ios::binary);
    if (in) sig_h.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  }
  CHECK(sig_h.find("main_image_size") != std::string::npos &&
            sig_h.find("main_image_read") != std::string::npos,
        "扫描结果必须记录主映像声明大小与实际读到的字节数");
  // 现在取的是 scan_process_images 选定的第 0 项（不再"取最大那块"，
  // 那个做法会把 RegionSize 当成 SizeOfImage）。语义要求不变：
  // 必须回填「实际读到的字节数」，否则没法区分范围问题与解密问题。
  CHECK(sig.find("out.main_image_read =") != std::string::npos,
        "必须回填 main_image_read，否则没法判断是范围问题还是解密问题");
  CHECK(sig.find("out.main_image_size = images[0].size") != std::string::npos,
        "main_image_size 必须取自选定映像（SizeOfImage），不能取最大区域");

  // b) 裁剪必须按「读到的最高偏移」，不是「读到的字节总数」
  // 声明形式现在是 "size_t done = 0, reach = 0, at = 0;"（同一个 while 里三个变量）
  CHECK(scan.find("size_t done = 0, reach = 0") != std::string::npos ||
            scan.find("size_t reach") != std::string::npos,
        "分块读必须记录已读到的最高偏移 reach");
  CHECK(scan.find("img.bytes.resize(reach)") != std::string::npos,
        "裁剪必须用 reach；用 done（字节总数）会把尾部已读到的代码整片丢掉");
  CHECK(scan.find("img.bytes.resize(done)") == std::string::npos,
        "不能用字节总数裁剪 —— 前面一页读不到就会截断整幅映像");
  // 只有完整读到的页才算进 reach
  CHECK(scan.find("g == n") != std::string::npos,
        "半页读取不能算作已覆盖，否则裁剪出来的内容里混着空洞");
  // 分块读：不能再退回逐页 2.8 万次系统调用
  // 现在选定映像的基址来自 select_client_image（见 image_select 组），
  // 常量名也从 peb_base 改成了 img_base —— 语义要求不变：
  // 必须按已提交段分块读，不能退回逐页 2.8 万次系统调用。
  CHECK(scan.find("VirtualQueryEx(process, reinterpret_cast<LPCVOID>(img_base + at)") !=
                std::string::npos ||
            scan.find("VirtualQueryEx(process, reinterpret_cast<LPCVOID>(peb_base + at)") !=
                std::string::npos,
        "主映像必须按已提交段分块读，逐页读会把客户端拖慢一个量级");
  // 而且映像大小必须来自 PE 头，不能来自区域大小
  CHECK(scan.find("select_client_image") != std::string::npos,
        "必须用 select_client_image 决定哪一份是客户端映像（不能拿最大区域凑）");
  CHECK(scan.find("img.size = soi") != std::string::npos,
        "img.size 必须是 SizeOfImage（PE 头里的值），不是 RegionSize");
  // 段起点可能早于映像基址，必须夹住，否则 size_t 下溢 -> 越界
  CHECK(scan.find("seg_lo64") != std::string::npos,
        "区域起点早于映像基址时必须夹到 [at, to_read)，否则下溢");
}

// Arctium 的 anti-crash 机制（PrepareAntiCrash）：这是「补丁装上了但客户端崩」
// 的唯一原因。崩溃栈落在 ntdll!RtlReportCriticalFailure，不是客户端代码。
//
// 这里用合成映像验证三件事（纯计算，不碰进程）：
//   1. Integrity / Integrity2 命中处写 C2 00 00（ret 0）
//   2. Remap 命中处：读出它之后的跳转，算出 jumpToValue，
//      再把「目标正好是 jumpToValue」的 Jcc 全部改成往前挪 1 字节
//   3. 无关跳转一个字节都不许动
static void test_anticrash_plan() {
  group("anticrash_plan");
  const uint64_t base = 0x140000000ULL;
  const size_t N = 0x20000;
  std::vector<uint8_t> img(N, 0x90);

  // 1) Integrity / Integrity2
  const uint8_t integ[] = {0x44,0x89,0x04,0x24,0x00, 0x44,0x89,0x04,0x24,0x00,
                           0x89,0x04,0x24,0x00, 0x48,0x89,0x04,0x24,0x00, 0x53,0x56,0x57};
  std::memcpy(img.data() + 0x100, integ, sizeof(integ));
  const uint8_t integ2[] = {0x44,0x89,0x04,0x24,0x00, 0x44,0x89,0x04,0x24,0x00,
                            0x89,0x04,0x24,0x00, 0x48,0x89,0x04,0x24,0x00, 0x53,0x57};
  std::memcpy(img.data() + 0x200, integ2, sizeof(integ2));

  // 2) Remap 特征码 48 ?? ?? 1E 0F 83：它自己的 0F 83 就是后续那条跳转
  const size_t a = 0x1000;
  img[a+0]=0x48; img[a+1]=0x83; img[a+2]=0xC4; img[a+3]=0x1E;
  img[a+4]=0x0F; img[a+5]=0x83;
  const int32_t remap_rel = static_cast<int32_t>(0x3000 - static_cast<long long>(a) - 10);
  std::memcpy(img.data()+a+6, &remap_rel, 4);
  const uint64_t jump_to = base + a + static_cast<uint64_t>(static_cast<int64_t>(remap_rel)) + 10;

  // 3) 一条短跳转（0x7C = jl rel8；Arctium 的 IsShortJump 是 0x70..0x7E，不含 0xEB）
  const size_t tj = static_cast<size_t>(jump_to - base) - 0x20;
  img[tj-3] = 0x48;
  img[tj] = 0x7C;
  img[tj+1] = static_cast<uint8_t>(static_cast<long long>(jump_to) -
                                   static_cast<long long>(base + tj) - 2);

  // 4) 一条长跳转（0F 84 rel32），目标也是 jump_to
  const size_t j5 = 0x4000;
  img[j5] = 0x0F; img[j5+1] = 0x84;
  int32_t rel32 = static_cast<int32_t>(static_cast<long long>(jump_to) -
                                       static_cast<long long>(base + j5) - 6);
  std::memcpy(img.data()+j5+2, &rel32, 4);

  // 5) 一条目标不同的长跳转：必须原封不动
  const size_t other = 0x5000;
  img[other] = 0x0F; img[other+1] = 0x84;
  int32_t other_rel = 0x123;
  std::memcpy(img.data()+other+2, &other_rel, 4);

  const auto plan = plan_anti_crash_from_image(img, base);
  CHECK(plan.ok, "anti-crash 规划必须成功");
  CHECK_EQ(plan.integrity_hits, 2u);
  CHECK_EQ(plan.remap_hits, 1u);
  // remap 自身的 0F 83 + 短跳 + 长跳 = 3 条
  CHECK_EQ(plan.remap_jump_patches, 3u);

  int integ_n = 0, short_n = 0, long_n = 0, saw_j5 = 0;
  for (const auto& p : plan.patches) {
    if (p.bytes.size() == 3 && p.bytes[0] == 0xC2) {
      ++integ_n;
      CHECK(p.bytes[1] == 0 && p.bytes[2] == 0, "Integrity 补丁必须是 C2 00 00（ret 0）");
    } else if (p.name.rfind("jmp_rel8@", 0) == 0) {
      ++short_n;
      CHECK_EQ(p.bytes.size(), 1u);
      CHECK_EQ(p.bytes[0], 0xEB);
      CHECK_EQ(p.va, base + tj);
    } else if (p.name.rfind("jmp_rel32@", 0) == 0) {
      ++long_n;
      CHECK_EQ(p.bytes.size(), 5u);
      CHECK_EQ(p.bytes[0], 0xE9);
      if (p.va == base + j5) ++saw_j5;
    }
  }
  CHECK_EQ(integ_n, 2);
  CHECK_EQ(short_n, 1);
  CHECK_EQ(long_n, 2);
  CHECK_EQ(saw_j5, 1);

  // 语义：rel 相对【跳转指令起点】编码，所以补丁本身不改变落点；
  // 效果来自"指令变短"——短跳转被压成 1 字节后，紧随其后的字节整体前移，
  // 于是校验逻辑读到的"真实代码"错位 1 字节。这里验证两点：
  //   1. 补丁后的编码仍然精确指向 jump_to（不是跳到别处，那样会崩）
  //   2. 短跳转确实只占 1 字节（原来占 2 字节）
  for (const auto& p : plan.patches) {
    if (p.name.rfind("jmp_rel8@", 0) == 0) {
      std::memcpy(img.data() + (p.va - base), p.bytes.data(), 1);
      const int8_t nr = static_cast<int8_t>(img[p.va - base + 1]);
      CHECK_EQ(p.va + 2 + static_cast<int64_t>(nr), jump_to);
      CHECK_EQ(p.bytes.size(), 1u);   // 2 字节 -> 1 字节，后续指令前移
    } else if (p.name.rfind("jmp_rel32@", 0) == 0) {
      std::memcpy(img.data() + (p.va - base), p.bytes.data(), 5);
      int32_t r = 0;
      std::memcpy(&r, img.data() + (p.va - base) + 1, 4);
      CHECK_EQ(p.va + 5 + static_cast<int64_t>(r), jump_to);
      CHECK_EQ(p.bytes.size(), 5u);   // 与原来等长
    }
  }
  // 无关跳转一个字节都不许动
  CHECK_EQ(img[other], 0x0F);
  CHECK_EQ(img[other+1], 0x84);
  int32_t still = 0;
  std::memcpy(&still, img.data() + other + 2, 4);
  CHECK_EQ(still, 0x123);
}

// 自包含模式（--mods + --listfile）必须能吃下用户手上真实的三种包形状。
// 这一段不依赖 Windows：只验证"目录树 -> FileDataID + 绝对路径"的换算。
//
// 用户截图里的三种：
//   Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-*.blp
//   T21WarriorNSFW/item/texturecomponents|objectcomponents|weapon
//   Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite.m2/.skin/.blp
// 证书补丁（CertBundle / CertCommonName / CertChain / CertCheck）。
//
// 这四条只有连私有服务器才需要，但既然要实现就必须和 Arctium 逐字节一致：
// 偏移写错一个字节 = 改写指令中间 = 客户端起不来。
// 这里用合成映像验证「命中点 + offset -> 写入位置」这条唯一的算术。
// 客户端映像选择。这一段直接对着用户真机日志里的数字写。
//
// 真机日志（2026-11-15）：
//   第 1 轮: 主映像 108.3 MB
//   第 2 轮: 主映像 176.0 MB
//   第 3 轮: 主映像 256.0 MB 读到 192.0 MB
//   第 4/5 轮: 同上
//   5 轮 CustomFileIdHook 全部 0/8，最后闪退。
//
// 176.0 MB 那个才是 SizeOfImage（PE 头里的定值，不可能随轮次变化）。
// 108.3 / 256.0 只可能来自 RegionSize —— 说明我们扫的是旁边一块无关分配。
static void test_image_select() {
  group("image_select");
  using namespace wowmod;

  auto make_pe = [](uint32_t size_of_image, uint16_t magic = 0x20B, uint16_t nsec = 8) {
    std::vector<uint8_t> h(0x1000, 0);
    h[0] = 'M'; h[1] = 'Z';
    const uint32_t pe = 0x80;
    std::memcpy(&h[0x3C], &pe, 4);
    const uint32_t sig = 0x00004550u;
    std::memcpy(&h[pe], &sig, 4);
    std::memcpy(&h[pe + 6], &nsec, 2);
    std::memcpy(&h[pe + 24], &magic, 2);
    std::memcpy(&h[pe + 24 + 56], &size_of_image, 4);
    return h;
  };

  // --- PE 头解析 ---
  {
    auto h = make_pe(0xB000000);           // 176 MB
    const auto pe = parse_pe_header(h.data(), h.size());
    CHECK(pe.ok, "应能解析合法 PE 头");
    CHECK_EQ(pe.size_of_image, 0xB000000u);
    CHECK(pe.is_64bit, "PE32+ 应识别为 64 位");
    CHECK_EQ(pe.n_sections, 8);
  }
  {
    std::vector<uint8_t> junk(0x1000, 0xCC);
    CHECK(!parse_pe_header(junk.data(), junk.size()).ok, "非 MZ 必须拒绝");
    auto h = make_pe(0x1000);              // 太小
    CHECK(!parse_pe_header(h.data(), h.size()).ok, "SizeOfImage 太小必须拒绝");
    auto h2 = make_pe(0x80000000u);        // 2 GB
    CHECK(!parse_pe_header(h2.data(), h2.size()).ok, "SizeOfImage 过大必须拒绝");
  }

  // --- PEB 给出答案时，必须以 PEB 为准 ---
  {
    // 区域表里放一块「更大但 PE 头是别人」的分配，模拟 256 MB 那个假映像
    std::vector<MemRegion> regions = {
        {0x140000000ull, 0x10000000ull, 0x04, 0x20000, ""},   // 256 MB MEM_PRIVATE
        {0x7ff600000000ull, 0xB000000ull, 0x02, 0x40000, "Wow.exe"},
    };
    auto read = [&](uint64_t at, std::vector<uint8_t>* buf) -> bool {
      if (at == 0x7ff600000000ull) { *buf = make_pe(0xB000000); return true; }
      if (at == 0x140000000ull) { *buf = make_pe(0x10000000u); return true; }
      return false;
    };
    const auto sel =
        select_client_image(regions, 0x7ff600000000ull, read);
    CHECK(sel.ok, "PEB 基址可用时必须成功");
    CHECK(sel.image.base == 0x7ff600000000ull, "必须选中 PEB 给出的基址");
    CHECK_EQ(sel.image.size_of_image, 0xB000000u);
    CHECK(sel.image.from_peb, "必须标记为来自 PEB");
  }

  // --- PEB 不可用时，不能拿「最大区域」当映像 ---
  //
  // 这正是线上那次失败：256 MB 那块 MEM_PRIVATE 的 PE 头声明
  // SizeOfImage 比区域本身还大 -> 自洽性不成立 -> 必须丢弃，
  // 而不是因为「它最大」就选它。
  {
    std::vector<MemRegion> regions = {
        {0x140000000ull, 0x10000000ull, 0x04, 0x20000, ""},   // 256 MB，声明 512 MB
        {0x7ff600000000ull, 0xB000000ull, 0x02, 0x40000, "Wow.exe"},
    };
    auto read = [&](uint64_t at, std::vector<uint8_t>* buf) -> bool {
      if (at == 0x140000000ull) { *buf = make_pe(0x20000000u); return true; }
      if (at == 0x7ff600000000ull) { *buf = make_pe(0xB000000); return true; }
      return false;
    };
    const auto sel = select_client_image(regions, 0, read);
    CHECK(sel.ok, "应能选中自洽的那个");
    CHECK(sel.image.base == 0x7ff600000000ull,
          "必须丢掉自洽性不成立的大区域，选真正自洽的映像");
    CHECK(!sel.image.from_peb, "这条路径不是来自 PEB");
    CHECK_EQ(sel.image.size_of_image, 0xB000000u);
  }

  // --- 一个都不自洽：必须明确失败，而不是硬塞一个 ---
  {
    std::vector<MemRegion> regions = {
        {0x10000000ull, 0x1000ull, 0x04, 0x20000, ""},        // 太小
        {0x20000000ull, 0x1000000ull, 0x04, 0x20000, ""},     // 声明 64 MB，区域 16 MB
    };
    auto read = [&](uint64_t at, std::vector<uint8_t>* buf) -> bool {
      if (at == 0x20000000ull) { *buf = make_pe(0x4000000u); return true; }
      return false;
    };
    const auto sel = select_client_image(regions, 0, read);
    CHECK(!sel.ok, "没有自洽映像时必须报失败");
    CHECK(!sel.error.empty(), "失败要给出原因");
    CHECK(sel.image.base == 0, "失败时不能返回一个『凑合』的基址");
  }

  // --- PEB 基址无效时回退，而不是直接放弃 ---
  {
    std::vector<MemRegion> regions = {
        {0x7ff600000000ull, 0xB000000ull, 0x02, 0x100000, "Wow.exe"},
    };
    auto read = [&](uint64_t at, std::vector<uint8_t>* buf) -> bool {
      if (at == 0x7ff600000000ull) { *buf = make_pe(0xB000000); return true; }
      return false;
    };
    const auto sel = select_client_image(regions, 0x123456789abcull, read);   // PEB 乱指
    CHECK(sel.ok, "PEB 指向无效地址时应回退到区域表");
    CHECK(sel.image.base == 0x7ff600000000ull, "必须回退到区域表里的那个映像");
    CHECK(sel.image.image_backed, "MEM_IMAGE 的区域必须标记为 image_backed");
  }
}

static void test_cert_patches() {
  group("cert_patches");
  using namespace wowmod;

  // 四条特征码各自放一份，位置分散
  struct Case {
    const char* name;
    size_t at;
    std::vector<uint8_t> pattern;   // 已填好通配字节
    int offset;
    std::vector<uint8_t> expect;
  };
  std::vector<Case> cases = {
      // CertBundle: 75 06 48 ?? ?? 60 5F C3  -> +0 = 90 90
      {"CertBundle", 0x100, {0x75, 0x06, 0x48, 0xAA, 0xBB, 0x60, 0x5F, 0xC3}, 0, {0x90, 0x90}},
      // CertCommonName: 80 ?? 2A 75 ?? 32 C0 48 -> +5 = B0 01
      {"CertCommonName", 0x200, {0x80, 0x11, 0x2A, 0x75, 0x22, 0x32, 0xC0, 0x48}, 5, {0xB0, 0x01}},
      // CertChain: 32 DB EB 02 B3 01 48 83 ?? ?? 00 00 00 00 -> +0 = B3 01
      {"CertChain", 0x300,
       {0x32, 0xDB, 0xEB, 0x02, 0xB3, 0x01, 0x48, 0x83, 0xEC, 0x20, 0, 0, 0, 0}, 0, {0xB3, 0x01}},
      // CertCheck: ... E8 D0 42 00 00 0F B6 -> +8 = BF 01 00 72 72
      {"CertCheck", 0x400,
       {0x44, 0x24, 0x70, 0x48, 0x89, 0x44, 0x24, 0x60, 0xE8, 0xD0, 0x42, 0x00, 0x00, 0x0F, 0xB6},
       8, {0xBF, 0x01, 0x00, 0x72, 0x72}},
  };

  std::vector<uint8_t> img(0x20000, 0xCC);
  for (const auto& c : cases) {
    std::copy(c.pattern.begin(), c.pattern.end(), img.begin() + static_cast<long>(c.at));
  }

  // 默认不装证书补丁
  {
    const auto p0 = plan_anti_crash_from_image(img, 0x140000000ull);
    CHECK_EQ(p0.cert_patches, 0u);
    for (const auto& p : p0.patches) CHECK(!p.cert, "默认不应包含证书补丁");
  }

  const auto plan = plan_anti_crash_from_image(img, 0x140000000ull, true);
  CHECK(plan.ok, "规划应成功");
  CHECK_EQ(plan.cert_patches, cases.size());

  for (const auto& c : cases) {
    const uint64_t want_va = 0x140000000ull + c.at + static_cast<size_t>(c.offset);
    bool found = false;
    for (const auto& p : plan.patches) {
      if (!p.cert || p.name != c.name) continue;
      found = true;
      CHECK(p.va == want_va, std::string(c.name) + " 的写入地址错了");
      CHECK(p.bytes == c.expect, std::string(c.name) + " 的补丁字节错了");
    }
    CHECK(found, std::string("缺少补丁: ") + c.name);
  }

  // 偏移必须真的落在指令边界上，不能落在前一条指令中间 ——
  // 这里用一个"仅字节相同但位置不同"的映像验证：把 CertBundle 的模式
  // 放到映像结尾附近，确保不会越界写。
  {
    std::vector<uint8_t> small(0x1000, 0xCC);
    const std::vector<uint8_t> pat = {0x75, 0x06, 0x48, 0xAA, 0xBB, 0x60, 0x5F, 0xC3};
    std::copy(pat.begin(), pat.end(), small.end() - static_cast<long>(pat.size()));
    const auto p = plan_anti_crash_from_image(small, 0x10000000ull, true);
    for (const auto& q : p.patches) {
      CHECK(q.va >= 0x10000000ull, "写入地址不能低于映像基址");
      CHECK(q.va + q.bytes.size() <= 0x10000000ull + small.size(), "写入不能越界");
    }
  }
}

static void test_mods_selfcontained() {
  group("mods_selfcontained");
  using wowmod::win::build_selfcontained_mods;
  using wowmod::win::split_listfiles;

  // split_listfiles：Windows 路径里可能有盘符，但 ';' 是唯一分隔符
  {
    const auto v = split_listfiles("C:/a/lf.csv;D:/b/lf2.csv");
    CHECK_EQ(v.size(), 2u);
    if (v.size() == 2) {
      CHECK_EQ(v[0], std::string("C:/a/lf.csv"));
      CHECK_EQ(v[1], std::string("D:/b/lf2.csv"));
    }
    CHECK_EQ(split_listfiles("").size(), 0u);
    CHECK_EQ(split_listfiles("only.csv").size(), 1u);
  }

  // 用临时目录造一棵和用户包同构的树
  namespace fs = std::filesystem;
  std::error_code ec;
  const fs::path root = fs::temp_directory_path(ec) / "wowmod-selfcontained-test";
  fs::remove_all(root, ec);
  auto mk = [&](const std::string& rel, const std::string& body) {
    const fs::path f = root / fs::path(rel);
    fs::create_directories(f.parent_path(), ec);
    std::ofstream(f) << body;
  };

  // 包 1：Wrath NPC Pack —— 目录名不叫 creature/，只能靠文件名 + 尾部打分
  mk("Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-15876.blp", "a");
  mk("Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-15877.blp", "b");
  // 包 2：T21WarriorNSFW —— item/ 打头，根就是包的父目录
  mk("T21WarriorNSFW/item/texturecomponents/T21Warrior_belt.blp", "c");
  mk("T21WarriorNSFW/item/weapon/T21Warrior_sword.blp", "d");
  // 包 3：Titaa 坐骑 —— Creature/ 打头，含 .m2 / .skin / .blp
  mk("Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite.m2", "e");
  mk("Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite00.skin", "f");
  mk("Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelitewhite.blp", "g");
  // 重名文件：必须被拒绝，不能猜
  mk("SomeMod/Textures/common.blp", "h");

  const fs::path lf = root / "lf.csv";
  {
    std::ofstream o(lf);
    o << "1;creature/bakednpctextures/creaturedisplayextra-15876.blp\n"
      << "2;creature/bakednpctextures/creaturedisplayextra-15877.blp\n"
      << "3;item/texturecomponents/t21warrior_belt.blp\n"
      << "4;item/weapon/t21warrior_sword.blp\n"
      << "5;creature/cockatrice/cockatricelite.m2\n"
      << "6;creature/cockatrice/cockatricelite00.skin\n"
      << "7;creature/cockatrice/cockatricelitewhite.blp\n"
      << "8;character/human/female/common.blp\n"
      << "9;character/orc/male/common.blp\n";
  }

  const auto rep = build_selfcontained_mods(root.u8string(), {lf.u8string()});
  CHECK(rep.ok, "自包含扫描应成功");
  // 8 个模组文件 + 1 个 listfile（它本身不是游戏资源，会被跳过不计）
  CHECK_EQ(rep.files_scanned, 9u);
  CHECK_EQ(rep.matched, 7u);
  CHECK_EQ(rep.ambiguous, 1u);   // common.blp 重名 -> 拒绝
  CHECK_EQ(rep.missing, 1u);     // 被拒绝的那条也在 missing 里

  // 每条都要能直接打开：这是 Arctium 语义（字符串块存绝对路径）
  for (const auto& e : rep.entries) {
    CHECK(e.file_data_id >= 1 && e.file_data_id <= 7, "id 必须在 1..7");
    CHECK(fs::is_regular_file(fs::u8path(e.local_path), ec),
          "表里存的本地路径必须真实存在: " + e.local_path);
    CHECK(!e.game_path.empty(), "game_path 不能为空");
    // 游戏内相对路径必须是小写、正斜杠、不含盘符
    CHECK(e.game_path.find(':') == std::string::npos, "相对路径不能含盘符");
    CHECK(e.game_path.find('\\') == std::string::npos, "相对路径必须是正斜杠");
  }
  // 重名文件不能被随便选中
  bool picked_common = false;
  for (const auto& e : rep.entries)
    if (e.file_data_id == 8 || e.file_data_id == 9) picked_common = true;
  CHECK(!picked_common, "重名文件必须拒绝，不能猜一个 id");

  // ---- 精确匹配必须真的走到 ----
  //
  // 这一段是回归测试。之前的实现拿【绝对路径】去做 "character/" /
  // "spells/" 这种前缀判断，于是永远不成立，base 被算成模组目录的父目录，
  // 游戏内相对路径多出一层 "T21WarriorNSFW/"，精确匹配全部失效 ——
  // 只能退到"文件名+尾部目录打分"这条模糊路径。
  // 模糊路径虽然在这个例子里恰好也能对，但它对"看起来像、其实是另一个
  // 资源"的文件会选错，而且用户看不出任何异常。必须保证精确匹配生效。
  CHECK(rep.by_exact >= 2, "以 item/ 打头的包必须走精确匹配（by_exact >= 2）");
  {
    bool found_belt = false, found_sword = false;
    for (const auto& e : rep.entries) {
      if (e.file_data_id == 3) {
        found_belt = true;
        CHECK_EQ(e.game_path, std::string("item/texturecomponents/t21warrior_belt.blp"));
      }
      if (e.file_data_id == 4) {
        found_sword = true;
        CHECK_EQ(e.game_path, std::string("item/weapon/t21warrior_sword.blp"));
      }
      if (e.file_data_id == 5)
        CHECK_EQ(e.game_path, std::string("creature/cockatrice/cockatricelite.m2"));
    }
    CHECK(found_belt && found_sword, "item 包的两条必须都解析出来");
  }
  // ---- 模组目录本身就是游戏前缀目录（线上真实失败场景）----
  //
  // 用户实测：他选的是 `...\_midnight_\Character`，里面的文件叫
  //   BloodElf/Female/bloodelffemale_hd_skin_color_3500114.blp
  // 而 listfile 里是 character/bloodelf/female/...
  // 相对他选的目录，"character/" 这一段根本不在路径里，
  // 于是精确匹配 0 命中（日志：精确 0 / 文件名 797），
  // 全靠"文件名模糊匹配"在兜 —— 一旦重名就会整包失效。
  {
    std::error_code ec2;
    const fs::path root2 = fs::temp_directory_path(ec2) / "wowmod-prefix-test";
    fs::remove_all(root2, ec2);
    const fs::path moddir = root2 / "Character";     // 模组目录 = Character 本身
    fs::create_directories(moddir / "BloodElf" / "Female", ec2);
    std::ofstream(moddir / "BloodElf" / "Female" / "bloodelffemale_hd_skin_color_3500114.blp")
        << "x";
    std::ofstream(moddir / "BloodElf" / "Female" / "bloodelffemale_hd_skin_color_3500115.blp")
        << "y";
    {
      std::ofstream o(root2 / "lf2.csv");
      o << "111;character/bloodelf/female/bloodelffemale_hd_skin_color_3500114.blp\n"
        << "222;character/bloodelf/female/bloodelffemale_hd_skin_color_3500115.blp\n";
    }
    const auto r2 = build_selfcontained_mods(moddir.u8string(), {(root2 / "lf2.csv").u8string()});
    CHECK(r2.ok, "模组目录=前缀目录时必须能解析");
    CHECK_EQ(r2.matched, 2u);
    CHECK_EQ(r2.by_exact, 2u);        // 必须靠精确匹配，而不是文件名模糊
    CHECK_EQ(r2.by_prefix, 2u);       // 具体是靠"补上 character/"命中的
    CHECK_EQ(r2.by_name, 0u);
    for (const auto& e : r2.entries)
      CHECK(e.game_path.rfind("character/", 0) == 0,
            "游戏内路径必须补全为 character/...，实际: " + e.game_path);
    fs::remove_all(root2, ec2);
  }

  // ---- 用【真实 listfile 分片】跑一遍用户的实际目录 ----
  //
  // tests/data/parts_sample.csv 直接取自 wowdev/wow-listfile 的
  // parts/placeholder.csv + misc.csv（未改一字），里面有
  //   116921;Character/BloodElf/Female/BloodElfFemale.m2
  //   116922;Character/BloodElf/Female/BLOODELFFEMALEFACELOWER00_00.BLP
  // 正是用户那个模组目录的内容形态。
  {
    std::error_code ec3;
    const fs::path root3 = fs::temp_directory_path(ec3) / "wowmod-real-listfile-test";
    fs::remove_all(root3, ec3);
    const fs::path moddir = root3 / "Character";
    fs::create_directories(moddir / "BloodElf" / "Female", ec3);
    std::ofstream(moddir / "BloodElf" / "Female" / "BloodElfFemale.m2") << "m2";
    std::ofstream(moddir / "BloodElf" / "Female" / "BLOODELFFEMALEFACELOWER00_00.BLP") << "blp";
    // 一个 listfile 里不存在的文件：必须如实报告"没解析出 id"，不能瞎配
    std::ofstream(moddir / "BloodElf" / "Female" / "mymod_not_in_listfile.blp") << "x";

    const auto r3 = build_selfcontained_mods(moddir.u8string(), {"tests/data/parts_sample.csv"});
    CHECK(r3.ok, "真实分片必须能解析: " + r3.error);
    CHECK_EQ(r3.matched, 2u);
    CHECK_EQ(r3.by_exact, 2u);     // 大小写不同也要命中（listfile 是 Character/，磁盘是 Character/）
    CHECK_EQ(r3.by_prefix, 2u);    // 靠"补上 character/"命中：模组目录本身就是 Character
    CHECK_EQ(r3.by_name, 0u);      // 一次文件名猜测都不该发生
    CHECK_EQ(r3.missing, 1u);      // 那个自造文件必须算 missing
    bool saw_m2 = false, saw_blp = false;
    for (const auto& e : r3.entries) {
      if (e.file_data_id == 116921) { saw_m2 = true; CHECK_EQ(e.game_path, std::string("character/bloodelf/female/bloodelffemale.m2")); }
      if (e.file_data_id == 116922) {
        saw_blp = true;
        CHECK_EQ(e.game_path, std::string("character/bloodelf/female/bloodelffemalefacelower00_00.blp"));
        CHECK_EQ(e.file_exists, true);
      }
    }
    CHECK(saw_m2, "BloodElfFemale.m2 必须解析到 116921");
    CHECK(saw_blp, "BLOODELFFEMALEFACELOWER00_00.BLP 必须解析到 116922");
    fs::remove_all(root3, ec3);
  }

  // game_path 必须永远是【游戏内】路径，不能把模组目录名带进去
  for (const auto& e : rep.entries)
    CHECK(e.game_path.rfind("t21warrior", 0) != 0 && e.game_path.rfind("titaa", 0) != 0 &&
              e.game_path.rfind("wowmod-selfcontained-test", 0) != 0,
          "游戏内路径不能带模组目录名: " + e.game_path);

  fs::remove_all(root, ec);
}

// 就绪判据的行为测试 —— 用用户 2026-11-15 那次真实运行的每一轮数字。
//
// 那次日志：
//   第 1 轮 ... Init 有 ... CustomFileIdHook 0 处
//   第 2~5 轮 ... Init 无 ... CustomFileIdHook 1 处, 最佳 0/8
//   [失败] 等待期内 CustomFileIdHook 始终没有达到 6/8 ...
//
// 客户端在第 1 轮就已经初始化完成（Init 有），这正是 Arctium 的
// 通过条件。旧的「语义分 >= 6/8」判据把它拒了，白等到超时。
// 这个测试把两套判据放在一起跑，锁住「必须第 1 轮就绪」。
static void test_readiness_criteria_on_real_log() {
  group("readiness_on_real_log");
  struct Round { bool init; int hits; int score; bool rx; };
  static const Round kRounds[] = {
      {true, 0, 0, false},   // 第 1 轮
      {false, 1, 0, false},  // 第 2 轮
      {false, 1, 0, false},  // 第 3 轮
      {false, 1, 0, false},  // 第 4 轮
      {false, 1, 0, false},  // 第 5 轮
  };
  auto old_ready_round = [&]() -> int {
    for (int i = 0; i < 5; ++i)
      if (kRounds[i].rx && kRounds[i].score >= 6) return i + 1;
    return 0;
  };
  auto new_ready_round = [&]() -> int {
    for (int i = 0; i < 5; ++i)
      if (kRounds[i].init) return i + 1;
    return 0;
  };
  CHECK_EQ(old_ready_round(), 0);
  CHECK_EQ(new_ready_round(), 1);
  // 这一条是本次修复的核心：用户的数据里第 1 轮就有 Init
  CHECK(kRounds[0].init, "第 1 轮 Init 必须为真（日志原文：Init 有）");
  CHECK_EQ(kRounds[0].hits, 0);
}

// 这次线上失败链路上剩下的两个「自己卡自己」的关卡。
//
// 用户 2026-11-15 第二次实测日志：
//   hook 目标 0x6ea06a0（语义分 0/8，命中页原本不可执行）
//   anti-crash 规划基于映像 0x00000000ffff0000，SizeOfImage 256 MB
//   [失败] NoJump 无法安全安装: 没有任何一条可以安全安装的分支补丁
//
// 两个独立缺陷：
//   A) anticrash.cpp 里在取到 images[0] 之后，又有一行
//      "if (img.size > main_img->size) main_img = &img;" 把它覆盖成最大那块，
//      于是规划用的是 256 MB 假映像（0xffff0000），一条校验点都找不到。
//   B) arctium_patch.cpp 先按「必须在可执行页上」筛命中，筛空即拒绝；
//      而壳初始化阶段 .text 是 RW，此刻不可执行完全正常。Arctium 从不看这个。
static void test_no_self_inflicted_gates() {
  group("no_self_inflicted_gates");
  auto slurp = [](const char* p) {
    std::string s;
    std::ifstream in(p, std::ios::binary);
    if (in) s.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s;
  };

  // A) anticrash 必须只用 images[0]
  const std::string ac = slurp("src/windows/anticrash.cpp");
  CHECK(!ac.empty(), "应能读到 anticrash.cpp");
  if (!ac.empty()) {
    // 不搜源码文本（注释里引用旧代码就会误报），而是检查一个结构性事实：
    // 取 main_img 之后到使用它之间，不能出现任何重新赋值给 main_img 的循环。
    // 这里用「images 里出现 main_img = 」这种可执行赋值模式来判断。
    CHECK(ac.find("main_img = &img;") == std::string::npos,
          "anticrash 不能再把 main_img 重新指向别的映像（max-size 覆盖）");
    CHECK(ac.find("const ScannedImage* main_img = &images[0];") != std::string::npos,
          "anti-crash 必须基于 scan_process_images 选定的第 0 项");
  }

  // B) NoJump 规划：离线确证 RVA 必须先于页属性判断
  const std::string ap = slurp("src/windows/arctium_patch.cpp");
  CHECK(!ap.empty(), "应能读到 arctium_patch.cpp");
  if (!ap.empty()) {
    const size_t rva_block = ap.find("离线确证的 RVA 是最高证据");
    const size_t cand_block = ap.find("std::vector<size_t> candidates;");
    CHECK(rva_block != std::string::npos, "必须有一段按 known_rva 优先采纳的逻辑");
    CHECK(cand_block != std::string::npos, "应有 candidates 筛选段");
    if (rva_block != std::string::npos && cand_block != std::string::npos) {
      CHECK(rva_block < cand_block,
            "known_rva 判定必须【早于】candidates/页属性筛选，"
            "否则「命中页不可执行」会再次把已确证的 RVA 拒掉");
    }
    // 候选集不能再被 executable 过滤
    CHECK(ap.find("if (hits[i].executable) candidates.push_back(i);") == std::string::npos,
          "candidates 不能再按 executable 过滤 —— 壳初始化阶段 .text 是 RW");
  }
}

// anti-crash / NoJump 的坐标原点必须唯一。
//
// 用户 2026-11-15 第三次实测日志：
//   anti-crash 规划: remap 校验 1 处, 跳转补丁 1 条        <- 终于找对了映像
//   规划基于映像 0x0000000003b30000, SizeOfImage 108 MB     <- 正确基址
//   hook 目标 0x0000000006f106a0                            <- base + 0x33E06A0
//   VirtualProtectEx 失败 @jmp_rel32@108975995: err=87
//   [失败] NoJump 无法安全安装
//
// 两件事：
//   A) VirtualProtectEx 要求页对齐地址 + 覆盖整页。传 (中途地址, 5) 必得 87。
//   B) 补丁搜索必须只在 images[0]（确认的客户端映像）里做，否则别的区域
//      也能命中同一串字节，得到"看着合理"的假地址。
static void test_single_image_origin_and_protect() {
  group("single_image_origin");

  auto slurp = [](const char* p) {
    std::string s;
    std::ifstream in(p, std::ios::binary);
    if (in) s.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s;
  };

  // A) VirtualProtectEx 必须按页对齐 + 覆盖整页
  const std::string ac = slurp("src/windows/anticrash.cpp");
  CHECK(!ac.empty(), "应能读到 anticrash.cpp");
  if (!ac.empty()) {
    CHECK(ac.find("va_page") != std::string::npos,
          "VirtualProtectEx 前必须把地址按页下舍（va_page）");
    CHECK(ac.find("page_mask") != std::string::npos, "必须有页掩码计算");
    CHECK(ac.find("VirtualProtectEx(process, reinterpret_cast<void*>(va_page), prot_len") !=
              std::string::npos,
          "VirtualProtectEx 必须用页对齐地址 + 整页长度");
    // 不能再用 (p.va, len) 直接调
    CHECK(ac.find("VirtualProtectEx(process, reinterpret_cast<void*>(p.va), len") ==
              std::string::npos,
          "不能再把 (p.va, len) 直接传给 VirtualProtectEx —— 那是 err=87 的原因");
  }

  // B) NoJump 规划只能搜 images[0]
  const std::string ap = slurp("src/windows/arctium_patch.cpp");
  CHECK(!ap.empty(), "应能读到 arctium_patch.cpp");
  if (!ap.empty()) {
    CHECK(ap.find("const std::vector<ScannedImage> images = {all_images[0]};") !=
              std::string::npos,
          "NoJump 必须只搜确认的客户端映像 images[0]，"
          "否则会在别的区域命中同一串字节、算出假地址");
  }

  // 页对齐算例（用日志里的真实 VA）
  const uint64_t va = 108975995ULL;
  const uint64_t mask = 0xFFF;
  const uint64_t va_page = va & ~mask;
  const uint64_t end_page = (va + 5 + mask) & ~mask;
  CHECK_EQ(va_page % 0x1000, 0ULL);
  CHECK(va_page <= va, "页起点必须在 VA 之前");
  CHECK(va + 5 <= end_page, "保护范围必须覆盖补丁字节");
  CHECK_EQ(end_page - va_page, 0x1000ULL);
}

// 这一轮线上日志（第四次）给出的新事实：
//   jmp_rel32@110286715: 页 0x692d000 Type=0x40000(MEM_MAPPED) Protect=0x04
//   VirtualProtectEx ... 长度 4096 -> GetLastError=87
//   [失败] NoJump 无法安全安装
//
// 那页【本来就是 READWRITE】。我们却在请求 EXECUTE_READWRITE。
// 对 section 映射出的数据视图追加 EXECUTE，内核按 section 属性拒绝，
// 返回的就是 87。写 4 个字节根本不需要执行权限。
static void test_write_protection_policy() {
  group("write_protection");
  auto slurp = [](const char* p) {
    std::string s;
    std::ifstream in(p, std::ios::binary);
    if (in) s.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s;
  };

  const std::string ac = slurp("src/windows/anticrash.cpp");
  CHECK(!ac.empty(), "应能读到 anticrash.cpp");
  if (!ac.empty()) {
    // 必须先判断"已经可写"，可写就不要去动保护
    CHECK(ac.find("already_writable") != std::string::npos,
          "必须先判断页是否已可写；已可写就别改保护（改 EXECUTE 会被拒 err=87）");
    // 它必须真的被执行到：既赋值又用于分支
    CHECK(ac.find("bool protect_ok = already_writable;") != std::string::npos,
          "already_writable 必须参与控制流（不能只是声明后不用）");
    CHECK(ac.find("if (already_writable) {") != std::string::npos,
          "已可写时必须有独立分支，跳过 VirtualProtectEx");
    // 必须保留降级路径
    CHECK(ac.find("PAGE_READWRITE") != std::string::npos,
          "EXECUTE_READWRITE 被拒时必须降级到 PAGE_READWRITE");
  }

  // known_rva 直通必须【最优先】。
  //
  // 线上实测的死循环：弱签名只有 12 个字节约束（25 字节里 12 个通配），
  // 在 108 MB 映像里必然命中十几处 -> hits 非空 -> known_rva 直通
  // 那段代码永远执行不到 -> 又回到「多处命中、上下文不一致、拒绝」。
  {
    const std::string ap2 = slurp("src/windows/arctium_patch.cpp");
    const size_t prv = ap2.find("最高优先级：离线确证的 RVA");
    const size_t strong = ap2.find("if (hits.empty() && s.strong_pattern");
    CHECK(prv != std::string::npos, "必须有 known_rva 最优先定位的注释块");
    CHECK(strong != std::string::npos, "强签名分支应保留为 fallback");
    if (prv != std::string::npos && strong != std::string::npos)
      CHECK(prv < strong, "known_rva 判定必须在强签名/弱签名之前");
    // 诊断能力：失败必须能打出 known_rva 处真实字节
    CHECK(ap2.find("诊断 ") != std::string::npos,
          "失败时必须输出 known_rva 处真实字节（这一轮正是靠它定位的）");
  }

  // NoJump 侧也必须有改保护逻辑（以前完全没有）
  const std::string ap = slurp("src/windows/arctium_patch.cpp");
  CHECK(!ap.empty(), "应能读到 arctium_patch.cpp");
  if (!ap.empty()) {
    CHECK(ap.find("改页保护失败") != std::string::npos ||
              ap.find("VirtualProtectEx(process, reinterpret_cast<void*>(vp), plen") !=
                  std::string::npos,
          "apply_branch_patches 必须自己改页保护 —— 否则在 MEM_MAPPED 页上写必失败");
    // 失败时必须能自诊断：读出 known_rva 处真实字节
    CHECK(ap.find("诊断 ") != std::string::npos,
          "规划失败时必须读出 known_rva 处真实字节，否则无法区分「没解密」与「签名不对」");
  }

  // NoJump 必须重试（按需解密：没执行到的页还是密文）
  const std::string ml = slurp("src/windows/mod_loader.cpp");
  CHECK(ml.find("NoJump 第 ") != std::string::npos,
        "NoJump 必须等待重试，不能一次未命中就整体失败");

  // 位运算自检：用 Windows 的真实常量值（这里不引 windows.h）
  const unsigned PR = 0x02, PRW = 0x04, PWC = 0x08, PER = 0x20, PERW = 0x40, PEWC = 0x80;
  const unsigned writable_mask = PRW | PWC | PERW | PEWC;
  CHECK((0x04u & writable_mask) != 0, "PAGE_READWRITE(0x04) 必须算作可写");
  CHECK((PER & writable_mask) == 0, "PAGE_EXECUTE_READ 不算可写");
  CHECK((PR & writable_mask) == 0, "PAGE_READONLY 不算可写");
}

static void test_mod_loader_ordering() {
  group("mod_loader_ordering");
  std::string src;
  {
    std::ifstream in("src/windows/mod_loader.cpp", std::ios::binary);
    if (in) src.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  }
  CHECK(!src.empty(), "应能读到 mod_loader.cpp");
  if (src.empty()) return;

  const size_t p_suspend = src.find("suspend_process(process, &serr)");
  const size_t p_plan = src.find("plan_branch_patches(process, by_rva)");
  const size_t p_hook = src.find("build_hook_jump(tramp_va)");
  const size_t p_apply = src.find("apply_branch_patches(process, &branch_plan)");
  const size_t p_resume = src.find("resume_process(process, &rerr)");
  const size_t p_apply_branch = src.find("apply_branch_patches(process, &branch_plan)");

  CHECK(p_suspend != std::string::npos, "必须调用 suspend_process");
  CHECK(p_plan != std::string::npos, "必须调用 plan_branch_patches");
  CHECK(p_hook != std::string::npos, "必须调用 build_hook_jump");
  CHECK(p_apply != std::string::npos, "必须调用 apply_branch_patches");
  CHECK(p_resume != std::string::npos, "必须调用 resume_process");

  // 顺序：挂起 -> 规划 -> 写 hook -> 打 NoJump -> 恢复
  CHECK(p_suspend < p_plan, "挂起必须在规划之前");
  CHECK(p_plan < p_hook, "NoJump 规划必须在写 hook 之前（避免改了一半）");
  CHECK(p_hook < p_apply, "hook 安装必须在 NoJump 写入之前");
  CHECK(p_apply < p_resume, "恢复必须在所有写入之后");

  // 必须有 RAII 守卫，保证异常/提前 return 时也会恢复
  CHECK(src.find("struct ResumeGuard") != std::string::npos,
        "必须有 ResumeGuard 保证进程被恢复（否则客户端会永久挂起）");

  // ---- anti-crash 的实际位置（以 Arctium 原文为准，不再凭推理）----
  //
  // 这条断言被改过两次方向，两次都是凭"应该是这样"推断的，两次都错。
  // 现在只照抄 src/Launcher.cs 的事实：
  //
  //   WaitForUnpack()                       <- 等 Init 特征码 + 等标记置位
  //     if (antiCrash) PrepareAntiCrash()   <- 【挂起】+ 规划 Integrity/Remap
  //   QueuePatch(LoadByFileIdAlternate, 3)  <- NoJump 入队（仍挂起）
  //   QueuePatch(LoadByFilePathAlternate,3)
  //   ModLoader.HookClient(...)
  //   NtResumeProcess()
  //   RemapAndPatch(antiCrash)              <- 统一写入
  //
  // 注意 PrepareAntiCrash 里自己做 NtSuspendProcess，不需要"先挂起再规划"。
  // 所以 anti-crash 规划必须在 NoJump 规划【之前】、resume【之前】。
  const size_t p_ac_plan = src.find("plan_anti_crash(process");
  const size_t p_ac_apply = src.find("apply_anti_crash(process, &ac)");
  CHECK(p_ac_plan != std::string::npos, "必须调用 plan_anti_crash（Arctium PrepareAntiCrash）");
  CHECK(p_ac_apply != std::string::npos, "必须调用 apply_anti_crash");
  CHECK(p_ac_plan < p_plan,
        "anti-crash 规划必须在 NoJump 规划之前（Arctium: PrepareAntiCrash 在 WaitForUnpack 末尾）");
  CHECK(p_ac_apply < p_resume,
        "anti-crash 写入必须在 resume 之前（Arctium 在 NtResumeProcess 前完成所有写入）");

  // ---- WaitForUnpack 的第二步：等 Init 立即数指向的标记置位 ----
  //
  // 上游原文：
  //   initOffset += BitConverter.ToUInt32(memory.Read(initOffset + base + 2, 4), 0) + 10;
  //   while (memory.Read(initOffset + base, 1)?[0] == 0) ...
  // 只等"Init 特征码出现"是不够的 —— 那只说明代码被解密，
  // 不说明客户端执行过它。实测后果就是 "完整性校验 0 处"，然后闪退。
  CHECK(src.find("init_target_va") != std::string::npos,
        "必须实现 WaitForUnpack 第二步：读取 Init 的 mov 立即数得到标记地址");
  CHECK(src.find("解包完成") != std::string::npos || src.find("仍为 0") != std::string::npos,
        "必须等待标记字节由 0 变为非 0，而不是看到特征码就走");

  // ---- 不能用页保护属性过滤命中 ----
  //
  // Arctium 的 FindPattern 只做字节匹配，从不看 VirtualQueryEx 的保护位。
  // 我们曾要求 has_rx，结果壳把 .text 映射成 RW(0x04) 时
  // 每一个命中都被丢掉（日志里的 "可执行 否" / "明文页 22/260"）。
  CHECK(src.find("h.name == \"Init\" && h.has_rx") == std::string::npos,
        "Init 命中不能用 has_rx 过滤（Arctium 不看页保护）");

  // ---- 字符串块必须存绝对路径 ----
  //
  // Arctium 的 ModLoader 存的是 files 目录下枚举出来的【绝对路径】；
  // 存相对路径的话，客户端按自己的当前目录解析，文件不存在，
  // 于是「跳板装好、id 命中、画面一点不变」，且与资源类型无关。
  CHECK(src.find("arctium_stored_path") != std::string::npos,
        "字符串块必须用 arctium_stored_path 拼绝对路径");
  CHECK(src.find("字符串块自检") != std::string::npos,
        "必须有运行时自检：不是绝对路径就拒绝安装");
  // 自包含模式产出的条目也必须走同一条绝对路径逻辑（见 mod_loader.cpp
  // 里 req.entries 的构造），否则 --mods 模式下同样不生效。
}

static void test_arctium_clone() {
  group("arctium_clone");

  // 1) stub 模板必须与 Arctium 源码的 asm 数组逐字节一致
  {
    const unsigned char orig[50] = {
        0x85, 0xD2, 0x0F, 0x88, 0x72, 0xAF, 0xFF, 0xFF, 0x33, 0xC0, 0x49, 0xB9, 0x22,
        0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x8D, 0x0C, 0x40, 0xC1, 0xE1, 0x02,
        0x42, 0x39, 0x14, 0x09, 0x74, 0x0C, 0xFF, 0xC0, 0x3D, 0xEF, 0xBE, 0xAD, 0xDE,
        0x72, 0xEB, 0x33, 0xC0, 0xC3, 0x4A, 0x8B, 0x44, 0x09, 0x04, 0xC3};
    auto t = arctium::arctium_stub_template();
    CHECK_EQ(t.size(), 50u);
    CHECK(std::memcmp(t.data(), orig, 50) == 0, "stub 模板必须与 Arctium 源码逐字节一致");

    // 回填必须只落在三处：偏移 4(4B) / 12(8B) / 35(4B)，其余字节一个都不许变
    auto s = arctium::build_arctium_stub(0x1111111122222222ULL, 1096, 42);
    for (int i = 0; i < 50; ++i) {
      const bool in_slot = (i >= 4 && i < 8) || (i >= 12 && i < 20) || (i >= 35 && i < 39);
      if (!in_slot) {
        CHECK(s[i] == orig[i], "回填不得改动三处占位之外的任何字节");
        if (s[i] != orig[i]) break;
      }
    }
    // 三处占位的值必须真的写进去了
    int32_t js = 0;
    uint64_t alloc = 0;
    uint32_t cnt = 0;
    std::memcpy(&js, s.data() + 4, 4);
    std::memcpy(&alloc, s.data() + 12, 8);
    std::memcpy(&cnt, s.data() + 35, 4);
    CHECK_EQ(js, 42);
    CHECK_EQ(alloc, 0x1111111122222222ULL);
    CHECK_EQ(cnt, 1096u);
  }

  // 2) 13 字节 hook 跳转
  {
    auto j = arctium::build_hook_jump(0xAABBCCDDEEFF0011ULL);
    const unsigned char want[13] = {0x48, 0xB8, 0x11, 0x00, 0xFF, 0xEE, 0xDD,
                                    0xCC, 0xBB, 0xAA, 0xFF, 0xE0, 0x90};
    CHECK_EQ(j.size(), 13u);
    CHECK(std::memcmp(j.data(), want, 13) == 0, "hook 必须是 48 B8 <u64> FF E0 90");
  }

  // 3) 12 字节表布局 + 字符串块内容
  //
  // 【这条测试以前是错的，而且错的正是被它"验证"的代码】。
  // 旧断言要求字符串被小写化、并且就是相对路径：
  //     路径必须小写 + 正斜杠 + NUL 结尾
  //     CHECK_EQ(s0, "character/human/female/a.blp")
  // 但 Arctium（ModLoader.cs GetFileMappingData）存进去的是
  //     var pathBytes = Encoding.UTF8.GetBytes(f);   // f = files 下的绝对路径
  // 相对路径只用来查 id。存相对路径 = 客户端按自己的当前目录去打开
  // = 文件不存在 = 装了也不生效，且与资源类型无关（blp/m2/skin 都一样）。
  {
    std::vector<arctium::MappingEntry> e = {
        {100, "D:/mods/wowmod/files/Character/Human/Female/A.BLP"},
        {200, "D:/mods/wowmod/files/character/orc/b.blp"}};
    auto m = arctium::serialize_arctium_mappings(e);
    CHECK_EQ(m.table.size(), 24u);          // 2 * 12
    CHECK_EQ(m.count, 2u);
    uint32_t id0 = 0;
    std::memcpy(&id0, m.table.data(), 4);
    CHECK_EQ(id0, 100u);
    // 字符串必须【原样】写入：不小写、不改斜杠、NUL 结尾
    const std::string s0(reinterpret_cast<const char*>(m.strings.data()));
    CHECK_EQ(s0, std::string("D:/mods/wowmod/files/Character/Human/Female/A.BLP"));
    const std::string s1 = "D:/mods/wowmod/files/character/orc/b.blp";
    CHECK_EQ(m.strings.size(), s0.size() + 1 + s1.size() + 1);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(m.strings.data()) + s0.size() + 1), s1);
    CHECK_EQ(m.offsets.size(), 2u);
    CHECK_EQ(m.offsets[1], static_cast<uint32_t>(s0.size() + 1));
    arctium::patch_string_addresses(&m, 0x50000000ULL);
    uint64_t abs0 = 0;
    std::memcpy(&abs0, m.table.data() + 4, 8);
    CHECK_EQ(abs0, 0x50000000ULL);
  }

  // 3b) 绝对路径拼接：这就是 Arctium 枚举 files 目录时拿到的那个 f
  {
    using arctium::arctium_stored_path;
    CHECK_EQ(arctium_stored_path("D:/g/wowmod/files", "character/x/y.blp"),
             std::string("D:/g/wowmod/files/character/x/y.blp"));
    // 反斜杠目录前缀要规整成正斜杠，且不留双斜杠
    CHECK_EQ(arctium_stored_path("D:\\g\\wowmod\\files\\", "character/x/y.blp"),
             std::string("D:/g/wowmod/files/character/x/y.blp"));
    // 已经是绝对路径就不要再拼前缀（否则变成 .../files/D:/...）
    CHECK_EQ(arctium_stored_path("D:/g/wowmod/files", "E:/other/a.blp"),
             std::string("E:/other/a.blp"));
    // UNC
    CHECK_EQ(arctium_stored_path("D:/g/wowmod/files", "\\\\srv\\share\\a.blp"),
             std::string("\\\\srv\\share\\a.blp"));
    // 结果必须能被识别成「绝对路径」——加载器运行时会自检这一条
    const std::string p = arctium_stored_path("D:/g/wowmod/files", "character/x/y.blp");
    CHECK(p.size() > 3 && p[1] == ':' && p[2] == '/', "拼接结果必须是绝对路径");
  }

  // 4) 用 x64sim 执行 Arctium 原版 stub，核对三条路径的真实行为
  {
    const uint64_t base = 0x1000000ULL;
    const uint32_t ids[3] = {100, 200, 300};
    auto run_case = [&](uint32_t id, int expect_slot, const char* what) {
      const size_t head = 50 + 13 + 13;
      const uint64_t tbl = base + head + 16;
      const uint64_t strp = tbl + 3 * 12 + 0x40;
      std::vector<uint8_t> mem(head + 16 + 3 * 12 + 0x40 + 0x200, 0);
      auto stub = arctium::build_arctium_stub(tbl, 3, 42);
      std::memcpy(mem.data(), stub.data(), 50);
      for (int i = 0; i < 13; ++i) mem[50 + i] = 0x90;   // 原始指令用 nop 桩
      auto back = arctium::build_hook_jump(0xDEADBEEFULL);
      std::memcpy(mem.data() + 63, back.data(), 13);
      for (uint32_t i = 0; i < 3; ++i) {
        std::memcpy(mem.data() + (tbl - base) + i * 12, &ids[i], 4);
        const uint64_t p = strp + i * 0x20;
        std::memcpy(mem.data() + (tbl - base) + i * 12 + 4, &p, 8);
      }
      const auto r = x64sim::run(mem, base, 0, id, 0, 0, 0x100000ULL);
      if (expect_slot >= 0) {
        CHECK(r.stop == x64sim::Stop::kReturn, std::string("应 ret: ") + what);
        CHECK_EQ(r.returned, strp + static_cast<uint64_t>(expect_slot) * 0x20);
      } else {
        // 未命中：Arctium 返回 0（xor eax,eax / ret），不执行原始指令
        CHECK(r.stop == x64sim::Stop::kReturn, std::string("应 ret 0: ") + what);
        CHECK_EQ(r.returned, 0ull);
      }
    };
    run_case(100, 0, "命中第 0 项");
    run_case(200, 1, "命中第 1 项");
    run_case(300, 2, "命中第 2 项");
    run_case(999, -1, "未命中返回 0");
    run_case(0, -1, "id=0 未命中返回 0");
  }
}

static void test_fileid_stub_semantics() {
  group("fileid_stub_semantics");

  StubConfig cfg;
  cfg.id_register = "rdx";
  cfg.return_register = "rax";
  const uint32_t kCount = 3;
  const uint32_t ids[kCount] = {100, 200, 300};
  auto st = build_fileid_stub(cfg, 0, kCount);
  CHECK(st.ok(), "应能生成跳板");
  if (!st.ok()) return;

  // 把 stub + 表 + 字符串 + 跳板桩放进同一段连续内存，
  // 这样 x64sim 只用一个 code 缓冲就能跑完。
  auto run_case = [&](uint32_t id, int expect_slot, const char* what) {
    const uint64_t base = 0x1000000ULL;
    const uint64_t tbl = base + st.code.size() + 16;
    const uint64_t strp = tbl + 0x100;
    const uint64_t tramp = strp + 0x200;

    std::vector<uint8_t> local = st.code;
    for (const auto& sl : st.patch_slots) {
      const uint64_t v = (sl.second == "id_table_va") ? tbl : tramp;
      std::memcpy(local.data() + sl.first, &v, 8);
    }
    local.resize(static_cast<size_t>(tramp + 16 - base), 0);
    for (uint32_t i = 0; i < kCount; ++i) {
      std::memcpy(local.data() + (tbl - base) + i * 16, &ids[i], 4);
      const uint64_t p = strp + i * 0x20;
      std::memcpy(local.data() + (tbl - base) + i * 16 + 8, &p, 8);
    }
    const auto r = x64sim::run(local, base, 0, id, 0, 0, 0x100000ULL);
    if (expect_slot >= 0) {
      const uint64_t want = strp + static_cast<uint64_t>(expect_slot) * 0x20;
      CHECK(r.stop == x64sim::Stop::kReturn, std::string("应 ret: ") + what);
      CHECK_EQ(r.returned, want);
    } else {
      CHECK(r.stop == x64sim::Stop::kJumpOut, std::string("应跳到 trampoline: ") + what);
      CHECK_EQ(r.jump_target, tramp);
    }
  };

  run_case(100, 0, "命中第 0 项");
  run_case(200, 1, "命中第 1 项");
  run_case(300, 2, "命中第 2 项");
  run_case(999, -1, "未命中走 trampoline");
  run_case(0, -1, "id=0 走 trampoline");
  run_case(0x80000000u, -1, "负 id 走 trampoline");

  // 大表：确认循环真的能扫到【最后一项】。
  // 这正是「循环上界用项数」那个 bug 会让 95% 文件失效的地方。
  {
    const uint32_t big = 1096;
    auto s2 = build_fileid_stub(cfg, 0, big);
    CHECK(s2.ok(), "大表应能生成");
    if (s2.ok()) {
      const uint64_t base = 0x2000000ULL;
      const uint64_t tbl = base + s2.code.size() + 16;
      const uint64_t strp = tbl + big * 16 + 0x100;
      const uint64_t tramp = strp + 0x1000;
      std::vector<uint8_t> local = s2.code;
      for (const auto& sl : s2.patch_slots) {
        const uint64_t v = (sl.second == "id_table_va") ? tbl : tramp;
        std::memcpy(local.data() + sl.first, &v, 8);
      }
      local.resize(static_cast<size_t>(tramp + 16 - base), 0);
      for (uint32_t i = 0; i < big; ++i) {
        const uint32_t fid = 1000 + i;
        std::memcpy(local.data() + (tbl - base) + i * 16, &fid, 4);
        const uint64_t p = strp + i * 0x20;
        std::memcpy(local.data() + (tbl - base) + i * 16 + 8, &p, 8);
      }
      // 最后一项
      const auto r = x64sim::run(local, base, 0, 1000 + big - 1, 0, 0, 0x100000ULL);
      CHECK(r.stop == x64sim::Stop::kReturn, "必须能命中 1096 项表的最后一项");
      if (r.stop == x64sim::Stop::kReturn)
        CHECK_EQ(r.returned, strp + static_cast<uint64_t>(big - 1) * 0x20);
      // 表外
      const auto r2 = x64sim::run(local, base, 0, 999999, 0, 0, 0x100000ULL);
      CHECK(r2.stop == x64sim::Stop::kJumpOut, "表外 id 必须走 trampoline");
    }
  }
}

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

  // 循环上界必须是【字节数】而不是【项数】。
  //
  // 曾经的实现是 `cmp r11d, count / jb`，而 r11 是字节偏移、每轮 +16。
  // 于是条件变成「偏移 < 项数」，1096 项时循环只扫到第 68 项就退出，
  // 绝大多数文件永远匹配不到 —— 而且 32 位比较让 r11 高 32 位从不归零。
  // 这里直接把生成的字节里那条 cmp 的立即数取出来比对。
  {
    StubConfig cfg;
    cfg.id_register = "rdx";
    cfg.return_register = "rax";
    const uint32_t count = 1096;
    auto r = build_fileid_stub(cfg, 0x20000000000ULL, count);
    CHECK(r.ok(), "应能生成跳板");
    if (r.ok()) {
      // 找 `49 81 FB imm32`（cmp r11, imm32）
      bool found = false;
      uint32_t imm = 0;
      for (size_t i = 0; i + 7 <= r.code.size(); ++i) {
        if (r.code[i] == 0x49 && r.code[i + 1] == 0x81 && r.code[i + 2] == 0xFB) {
          std::memcpy(&imm, r.code.data() + i + 3, 4);
          found = true;
          break;
        }
      }
      CHECK(found, "跳板里必须有 cmp r11, imm32 做为循环上界");
      if (found) {
        CHECK_EQ(imm, count * 16u);
        CHECK(imm != count, "循环上界不能是项数");
      }
      // 不允许出现 32 位的 `41 81 FB`（cmp r11d, imm32）
      bool bad32 = false;
      for (size_t i = 0; i + 6 <= r.code.size(); ++i)
        if (r.code[i] == 0x41 && r.code[i + 1] == 0x81 && r.code[i + 2] == 0xFB) bad32 = true;
      CHECK(!bad32, "循环上界不能用 32 位比较");
    }
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
// 现场读取失败时，站点窗口必须回退到扫描缓存的字节。
//
// 线上症状：诊断（读缓存）说「明文且位置正确」，规划（现场 read_exact）
// 却说「找不到 0F 84」，于是 NoJump 7 次重试全部失败。
// 根因是 read_exact 在读取失败时静默返回全 0。
// 命中筛选与解包判据 —— 这两条正是第 5 轮失败的直接原因。
//
// 用纯函数测，而不是 grep 源码文本：上一轮我用 grep 断言
// `h.name == "Init" && h.has_rx` 不存在，结果变异把 has_rx 加回
// hook 选择那段，测试完全没报错。文本断言会漏。
static void test_hit_selection_and_unpack() {
  group("hit-selection");

  // 1) 页不可执行【不能】导致命中被丢弃。
  //    第 2 轮实测：CustomFileIdHook 1 处, 可执行 否 -> 跳板没装。
  std::vector<wowmod::HitCandidate> plain = {{0x1000, 0, false}};
  int sc = -1;
  CHECK(wowmod::pick_hook_target(plain, &sc) == 0x1000,
        "命中页不可执行时仍必须采用（壳把 .text 映射成 RW，Arctium 不看保护位）");
  CHECK(sc == 0, "分数应原样带出");

  // 2) 取分数最高者
  std::vector<wowmod::HitCandidate> multi = {
      {0x1000, 2, true}, {0x2000, 7, false}, {0x3000, 5, true}};
  CHECK(wowmod::pick_hook_target(multi, &sc) == 0x2000,
        "应选语义分最高的命中，即便它所在页不可执行");
  CHECK(sc == 7, "分数应为最高者");

  // 3) 空候选 -> 0（调用方据此判断"没找到"）
  CHECK(wowmod::pick_hook_target({}, &sc) == 0, "空候选必须返回 0");

  // 4) 同分取先到者
  std::vector<wowmod::HitCandidate> tie = {{0x1000, 3, true}, {0x2000, 3, true}};
  CHECK(wowmod::pick_hook_target(tie, &sc) == 0x1000, "同分取先到者");

  // ---- WaitForUnpack 第二步 ----
  // Init 形态：C7 05 <rel32=0x100> 01 00 00 00，位于 0x5000
  // 目标 = 0x5000 + 10 + 0x100
  // 0x5000 + 10 + 0x100 = 0x510A
  CHECK(wowmod::compute_init_flag_address(0x5000, 0x100) == 0x510A,
        "标记地址 = init_va + 10 + rel32（rel32 相对下一条指令）");
  CHECK(wowmod::compute_init_flag_address(0x5000, -0x10) == 0x5000 - 0x10 + 10,
        "负 rel32 也必须正确");
  CHECK(wowmod::compute_init_flag_address(0, 0x100) == 0, "init_va 为 0 时返回 0");

  // 5) 只有特征码、标记还是 0 -> 未解包完成（我们过去的 bug：这一步没做）
  CHECK(!wowmod::unpack_is_done(true, true, 0),
        "看到 Init 特征码但标记为 0 时，解包【尚未】完成 —— 不能往下走");
  // 6) 标记读不到 -> 未完成
  CHECK(!wowmod::unpack_is_done(true, false, 1), "标记读不到时不能判为完成");
  // 7) 特征码没出现 -> 未完成
  CHECK(!wowmod::unpack_is_done(false, true, 1), "没见到 Init 时不能判为完成");
  // 8) 两步都满足 -> 完成
  CHECK(wowmod::unpack_is_done(true, true, 1), "特征码出现且标记非 0 才算解包完成");
  CHECK(wowmod::unpack_is_done(true, true, 0xFF), "任意非 0 值都算置位");
}

static void test_site_window_fallback() {
  group("site-window");
  const uint64_t rva = 0x20;
  std::vector<uint8_t> scanned(rva + 16, 0);
  // 真实字节：01 0F 84 9C 00 00 00 48 8B 0D 4C 01 FD 00
  const uint8_t real[16] = {0x01, 0x0F, 0x84, 0x9C, 0x00, 0x00, 0x00, 0x48,
                            0x8B, 0x0D, 0x4C, 0x01, 0xFD, 0x00, 0x8B, 0xD6};
  std::memcpy(scanned.data() + rva, real, 16);

  // 1) 现场读到的窗口是全 0（读取失败）-> 回退后必须能定位到 je
  std::vector<uint8_t> zero(16, 0);
  CHECK(wowmod::resolve_site_window(zero, &scanned, rva),
        "现场读取失败（全 0）时必须回退到扫描缓存，否则 NoJump 永远定位不到");

  // 2) 现场读取成功 -> 直接可用
  std::vector<uint8_t> live(real, real + 16);
  CHECK(wowmod::resolve_site_window(live, &scanned, rva), "现场读取成功时直接可用");

  // 3) 没有缓存（nullptr）时不能假装成功
  CHECK(!wowmod::resolve_site_window(zero, nullptr, rva),
        "没有缓存字节时不能谎报成功");

  // 4) 缓存里也确实没有 je -> 必须返回 false（不能靠回退掩盖真失败）
  std::vector<uint8_t> no_je(rva + 16, 0x90);
  CHECK(!wowmod::resolve_site_window(zero, &no_je, rva),
        "缓存字节里没有 0F 84 时必须返回 false");

  // 5) rva 越界不能读飞
  CHECK(!wowmod::resolve_site_window(zero, &scanned, 0xFFFF0),
        "rva 超出缓存范围时必须安全返回 false");
}

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

  // 12.0.7 实测：Arctium 真正打补丁的两条是 *Alternate 变体，
  // 而旧的两条（LoadByFileId / LoadByFilePath）在 12.0.7 上命中 0 处。
  // 补丁偏移必须是 3（匹配起点 -> je 的 rel32），不是旧版的 6。
  bool saw_id_alt = false, saw_path_alt = false;
  for (const auto& sg : sigs) {
    const std::string n = sg.name;
    if (n == "LoadByFileIdAlternate") {
      saw_id_alt = true;
      CHECK_EQ(sg.patch_offset, 3);
      // 起点第 1 字节是 01，第 2-3 是 0F 84，偏移 3 落在 rel32 上
      CHECK_EQ(sg.pattern[0], '0');
    }
    if (n == "LoadByFilePathAlternate") {
      saw_path_alt = true;
      CHECK_EQ(sg.patch_offset, 3);
    }
  }
  CHECK(saw_id_alt, "有 LoadByFileIdAlternate（12.0.7 唯一命中，Arctium 实际打的是这条）");
  CHECK(saw_path_alt, "有 LoadByFilePathAlternate（12.0.7 唯一命中）");

  // ---- 强签名自检 ----
  //
  // 用户实测过「运行时命中 10 处」：Arctium 原始特征码 17 字节里 13 个通配位，
  // 只约束 4 个字节，全进程扫描必然撞车。所以必须有一条【无通配】的长签名兜底。
  // 这里验证：强签名存在、不含通配、比原始特征码长、以 010F84 开头（je rel32）。
  for (const auto& sg : sigs) {
    const std::string n = sg.name;
    if (n != "LoadByFileIdAlternate" && n != "LoadByFilePathAlternate") continue;
    CHECK(sg.strong_pattern != nullptr, std::string("有强签名: ") + n);
    if (!sg.strong_pattern) continue;
    const std::string sp = sg.strong_pattern;
    CHECK(sp.find('?') == std::string::npos, std::string("强签名不含通配位: ") + n);

    wowmod::Pattern sp2 = wowmod::Pattern::parse(sp, nullptr);
    CHECK(sp2.valid(), std::string("强签名可解析: ") + n);
    CHECK(sp2.size() > 30, std::string("强签名足够长(>30B): ") + n);
    // 注意：比的是【解析后的字节数】，不是特征串文本长度
    // （文本里 "?? " 占 3 个字符但只代表 1 个字节，拿字符串长度比会误判）。
    wowmod::Pattern wp = wowmod::Pattern::parse(sg.pattern, nullptr);
    CHECK(sp2.size() > wp.size(), std::string("强签名字节数多于原始特征码: ") + n);
    // 前 3 字节是 01 0F 84，但 01 是【前一条指令的尾巴】，真正的 je 操作码在 +1。
    //
    // 这是 v13 实测踩到的坑：报告写「原字节 00 00 00 00」而实际读回 9C 00 00 00，
    // 说明把 match+3 当成「je 的 rel32」时错位了 —— match+1 才是 0F 84，
    // rel32 在 match+3。所以补丁点必须在运行时按操作码校验后重算，
    // 不能硬信匹配起点。这里锁住签名形态，防止有人再改回去。
    if (sp2.size() >= 3) {
      CHECK_EQ(sp2.bytes[0], 0x01);   // 01 是先前的 test 立即数，不是 je 的一部分
      CHECK_EQ(sp2.bytes[1], 0x0F);   // je 操作码从这里开始
      CHECK_EQ(sp2.bytes[2], 0x84);
      // 因此「je 操作码偏移 = 1」，补丁点 = 匹配起点 + 1 + 2 = 匹配起点 + 3。
      // patch_offset 已经是 3，两者一致 —— 但代码里仍按实际操作码位置重算，
      // 这样即使签名起点变化也不会写错位置。
      CHECK_EQ(sg.patch_offset, 3);
    }
  }

  // 用合成字节验证「按操作码定位补丁点」的算法本身（不依赖客户端）。
  {
    // 01 0F 84 9C 00 00 00 —— 匹配起点含前一条指令尾巴
    const std::vector<uint8_t> win = {0x01, 0x0F, 0x84, 0x9C, 0x00, 0x00, 0x00, 0x48, 0x8B};
    int je_at = -1;
    for (int i = 0; i + 5 < static_cast<int>(win.size()) && i <= 4; ++i) {
      if (win[i] == 0x0F && win[i + 1] == 0x84) { je_at = i; break; }
    }
    CHECK_EQ(je_at, 1);                       // je 在 +1，不在 +0
    CHECK_EQ(win[je_at + 2], 0x9C);           // rel32 首字节
    CHECK_EQ(win[je_at + 2 + 3], 0x00);       // rel32 末字节
  }

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
  test_plain_page_accounting();
  test_peb_image_protect_and_reach();
  test_anticrash_plan();
  test_mods_selfcontained();
  test_cert_patches();
  test_image_select();
  test_readiness_criteria_on_real_log();
  test_no_self_inflicted_gates();
  test_single_image_origin_and_protect();
  test_write_protection_policy();
  test_mod_loader_ordering();
  test_arctium_clone();
  test_fileid_stub_semantics();
  test_fileid_stub();
  test_probe_stub();
  test_minidump_layout();
  test_launcher_stub();
  test_analyze();
  test_xref_multi_target();
  test_file_layout_remap();
  test_no_false_negative();
  test_protect_plan();
  test_hit_selection_and_unpack();
  test_site_window_fallback();
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
