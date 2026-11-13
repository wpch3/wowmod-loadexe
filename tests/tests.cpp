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
  teardown();
  std::cout << std::string(50, '-') << "\n";
  std::cout << g_total << " 项检查, " << g_failed << " 项失败\n";
  return g_failed ? 1 : 0;
}
