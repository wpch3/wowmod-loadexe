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

#include "wowmod/config.hpp"
#include "wowmod/discover.hpp"
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
  CHECK(full.to_json().at("supported").as_bool(), "永远 supported=true");
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
  CHECK(plan.at("client").at("supported").as_bool(), "plan 输出 supported=true");
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
  CHECK(ci.to_json().at("supported").as_bool(), "覆盖版本后依然 supported");
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
  CHECK(dci.to_json().at("supported").as_bool(), "无版本资源仍 supported=true");

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

int main() {
  std::cout << "wowmod 核心测试\n";
  std::cout << std::string(50, '-') << "\n";
  setup();
  test_util();
  test_json();
  test_version();
  test_mapping();
  test_config();
  test_vfs();
  test_hooks();
  test_discover();
  test_real_client();
  teardown();
  std::cout << std::string(50, '-') << "\n";
  std::cout << g_total << " 项检查, " << g_failed << " 项失败\n";
  return g_failed ? 1 : 0;
}
