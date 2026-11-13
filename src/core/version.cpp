// 版本探测实现：所有信息来自客户端文件，没有任何编译期版本表。
// SPDX-License-Identifier: MIT
#include "wowmod/version.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;
namespace wowmod {

namespace {

uint16_t rd16(const std::vector<uint8_t>& b, size_t off, bool* ok) {
  if (off + 2 > b.size()) { if (ok) *ok = false; return 0; }
  return static_cast<uint16_t>(b[off] | (b[off + 1] << 8));
}

uint32_t rd32(const std::vector<uint8_t>& b, size_t off, bool* ok) {
  if (off + 4 > b.size()) { if (ok) *ok = false; return 0; }
  return static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
         (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
}

uint64_t rd64(const std::vector<uint8_t>& b, size_t off, bool* ok) {
  uint32_t lo = rd32(b, off, ok);
  uint32_t hi = rd32(b, off + 4, ok);
  return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
}

std::string section_name(const std::vector<uint8_t>& b, size_t off) {
  std::string s;
  for (size_t i = 0; i < 8 && off + i < b.size() && b[off + i]; ++i) s.push_back(static_cast<char>(b[off + i]));
  return s;
}

// 私服客户端经常改写 VS_FIXEDFILEINFO 的四元组（例如本仓库上传的 12.0.7 Firestorm
// 写成 1200.7.6897.4），但 StringFileInfo 里的 FileVersion 仍是真实的 12.0.7.68974。
// 因此优先读字符串版本资源：它是给人看的，通常最可信。
std::string read_utf16(const std::vector<uint8_t>& b, size_t off, size_t wchars) {
  std::string out;
  for (size_t i = 0; i < wchars && off + i * 2 + 1 < b.size(); ++i) {
    uint16_t c = static_cast<uint16_t>(b[off + i * 2] | (b[off + i * 2 + 1] << 8));
    if (!c) break;
    out.push_back(c < 128 ? static_cast<char>(c) : '?');
  }
  return trim(out);
}

bool read_string_version(const std::vector<uint8_t>& b, size_t v, uint32_t data_size, ClientInfo* out) {
  size_t limit = std::min<size_t>(v + data_size, b.size());
  auto make_key = [](const char* s) {
    std::vector<uint8_t> k;
    for (const char* p = s; *p; ++p) { k.push_back(static_cast<uint8_t>(*p)); k.push_back(0); }
    k.push_back(0); k.push_back(0);
    return k;
  };
  for (const char* key_name : {"FileVersion", "ProductVersion"}) {
    const auto key = make_key(key_name);
    for (size_t p = v + 40; p + key.size() < limit; ++p) {
      if (p < 6 || b[p] != key[0] || b[p + 1] != key[1]) continue;
      if (!std::equal(key.begin(), key.end(), b.begin() + static_cast<ptrdiff_t>(p))) continue;
      size_t head = p - 6;  // String 结构: wLength wValueLength wType szKey
      if (head < v) continue;
      bool ok = true;
      uint16_t wlen = rd16(b, head, &ok), vlen = rd16(b, head + 2, &ok), wtype = rd16(b, head + 4, &ok);
      (void)wtype;
      if (!ok || vlen == 0 || vlen > 256 || wlen < key.size() + 6 || wlen > 4096) continue;
      size_t val = (p + key.size() + 3) & ~static_cast<size_t>(3);
      std::string s = read_utf16(b, val, vlen);
      if (s.empty()) continue;
      ClientInfo tmp;
      if (!parse_version_string(s, &tmp.major, &tmp.minor, &tmp.patch, &tmp.build)) continue;
      if (tmp.major <= 0 || tmp.major > 100) continue;  // 明显不是 WoW 版本号
      out->major = tmp.major; out->minor = tmp.minor; out->patch = tmp.patch; out->build = tmp.build;
      out->version_string = s;
      out->notes.push_back("版本号取自 exe 的 StringFileInfo/" + std::string(key_name) + "（私服常改写二进制版本字段）");
      return true;
    }
  }
  return false;
}

// 遍历 PE 资源树，寻找 RT_VERSION (16) 并解析 VS_FIXEDFILEINFO。
bool read_version_resource(const PeImage& pe, uint32_t resource_rva, ClientInfo* out) {
  auto root = pe.rva_to_offset(resource_rva);
  if (!root) return false;
  const auto& b = pe.bytes;
  bool ok = true;
  size_t ro = *root;

  // 收集第 1 层中 ID == 16 的目录项
  uint16_t named = rd16(b, ro + 12, &ok);
  uint16_t ids = rd16(b, ro + 14, &ok);
  if (!ok) return false;
  std::vector<uint32_t> level2;
  for (uint32_t i = 0; i < static_cast<uint32_t>(named) + ids; ++i) {
    size_t eo = ro + 16 + static_cast<size_t>(i) * 8;
    uint32_t name = rd32(b, eo, &ok);
    uint32_t off = rd32(b, eo + 4, &ok);
    if (!ok) return false;
    if (!(name & 0x80000000u) && (name & 0xFFFFu) == 16 && (off & 0x80000000u)) level2.push_back(resource_rva + (off & 0x7FFFFFFFu));
  }
  if (level2.empty()) return false;

  for (uint32_t dir2_rva : level2) {
    auto d2 = pe.rva_to_offset(dir2_rva);
    if (!d2) continue;
    uint16_t n2 = rd16(b, *d2 + 12, &ok), i2 = rd16(b, *d2 + 14, &ok);
    std::vector<uint32_t> level3;
    for (uint32_t i = 0; i < static_cast<uint32_t>(n2) + i2; ++i) {
      uint32_t off = rd32(b, *d2 + 16 + static_cast<size_t>(i) * 8 + 4, &ok);
      if (ok && (off & 0x80000000u)) level3.push_back(resource_rva + (off & 0x7FFFFFFFu));
    }
    for (uint32_t dir3_rva : level3) {
      auto d3 = pe.rva_to_offset(dir3_rva);
      if (!d3) continue;
      uint16_t n3 = rd16(b, *d3 + 12, &ok), i3 = rd16(b, *d3 + 14, &ok);
      for (uint32_t i = 0; i < static_cast<uint32_t>(n3) + i3; ++i) {
        uint32_t off = rd32(b, *d3 + 16 + static_cast<size_t>(i) * 8 + 4, &ok);
        if (!ok || (off & 0x80000000u)) continue;  // 应是 IMAGE_RESOURCE_DATA_ENTRY
        auto de = pe.rva_to_offset(resource_rva + off);
        if (!de) continue;
        uint32_t data_rva = rd32(b, *de, &ok);
        uint32_t data_size = rd32(b, *de + 4, &ok);
        if (!ok || data_size < 52 || data_size > 65535) continue;
        auto vo = pe.rva_to_offset(data_rva);
        if (!vo) continue;
        // VS_VERSIONINFO 头: wLength(2) wValueLength(2) wType(2) szKey("VS_VERSION_INFO"\0)
        // Value 4 字节对齐后是 VS_FIXEDFILEINFO
        size_t v = *vo;
        size_t key_start = v + 6;
        size_t k = key_start;
        while (k + 1 < b.size() && k + 1 < v + data_size && !(b[k] == 0 && b[k + 1] == 0)) k += 2;
        k += 2;
        size_t fixed = (k + 3) & ~static_cast<size_t>(3);
        if (fixed + 52 > b.size()) continue;
        uint32_t sig = rd32(b, fixed, &ok);
        if (!ok || sig != 0xFEEF04BDu) continue;
        // 字符串版本优先：私服把 VS_FIXEDFILEINFO 改成 1200.7.6897.4 时仍能得到 12.0.7.68974
        if (read_string_version(b, v, data_size, out)) return true;
        uint32_t ms = rd32(b, fixed + 8, &ok);
        uint32_t ls = rd32(b, fixed + 12, &ok);
        if (!ok) continue;
        out->major = static_cast<int>(ms >> 16);
        out->minor = static_cast<int>(ms & 0xFFFFu);
        out->patch = static_cast<int>(ls >> 16);
        out->build = static_cast<int>(ls & 0xFFFFu);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d", out->major, out->minor, out->patch, out->build);
        out->version_string = buf;
        return true;
      }
    }
  }
  return false;
}

// 兜底：资源目录解析失败时，直接扫描 VS_FIXEDFILEINFO 签名。
bool scan_version_signature(const std::vector<uint8_t>& b, ClientInfo* out) {
  for (size_t i = 0; i + 40 < b.size(); ++i) {
    if (b[i] == 0xBD && b[i + 1] == 0x04 && b[i + 2] == 0xEF && b[i + 3] == 0xFE) {
      bool ok = true;
      uint32_t ms = rd32(b, i + 8, &ok), ls = rd32(b, i + 12, &ok);
      if (!ok) continue;
      int major = static_cast<int>(ms >> 16), build = static_cast<int>(ls & 0xFFFFu);
      if (major == 0 || major > 100 || build == 0) continue;
      out->major = major;
      out->minor = static_cast<int>(ms & 0xFFFFu);
      out->patch = static_cast<int>(ls >> 16);
      out->build = build;
      char buf[64];
      std::snprintf(buf, sizeof(buf), "%d.%d.%d.%d", out->major, out->minor, out->patch, out->build);
      out->version_string = buf;
      return true;
    }
  }
  return false;
}

}  // namespace

bool PeImage::load(const std::vector<uint8_t>& data, std::string* err) {
  bytes = data;
  ok = false;
  bool okr = true;
  if (bytes.size() < 0x40 || rd16(bytes, 0, &okr) != 0x5A4D || !okr) {
    if (err) *err = "不是有效的 PE 文件 (缺少 MZ)";
    return false;
  }
  uint32_t pe_off = rd32(bytes, 0x3C, &okr);
  if (!okr || pe_off + 24 > bytes.size() || rd32(bytes, pe_off, &okr) != 0x00004550u || !okr) {
    if (err) *err = "不是有效的 PE 文件 (缺少 PE 头)";
    return false;
  }
  machine = rd16(bytes, pe_off + 4, &okr);
  uint16_t num_sections = rd16(bytes, pe_off + 6, &okr);
  uint16_t opt_size = rd16(bytes, pe_off + 20, &okr);
  uint32_t opt = pe_off + 24;
  uint16_t magic = rd16(bytes, opt, &okr);
  if (!okr) { if (err) *err = "PE 可选头截断"; return false; }

  uint32_t dir_off = 0;
  if (magic == 0x10B) {           // PE32
    dir_off = opt + 96;
    image_base = rd32(bytes, opt + 28, &okr);
  } else if (magic == 0x20B) {    // PE32+
    dir_off = opt + 112;
    image_base = rd64(bytes, opt + 24, &okr);
  } else {
    if (err) *err = "未知的 PE 可选头 magic";
    return false;
  }
  // NumberOfRvaAndSizes
  uint32_t num_dirs = rd32(bytes, magic == 0x10B ? opt + 92 : opt + 108, &okr);
  uint32_t resource_rva = 0;
  if (okr && num_dirs > 2 && dir_off + 3 * 8 <= opt + opt_size) resource_rva = rd32(bytes, dir_off + 2 * 8, &okr);

  uint32_t sec_off = opt + opt_size;
  for (uint32_t i = 0; i < num_sections && sec_off + 40 <= bytes.size(); ++i, sec_off += 40) {
    Section s;
    s.name = section_name(bytes, sec_off);
    s.vsize = rd32(bytes, sec_off + 8, &okr);
    s.rva = rd32(bytes, sec_off + 12, &okr);
    s.raw_size = rd32(bytes, sec_off + 16, &okr);
    s.raw_ptr = rd32(bytes, sec_off + 20, &okr);
    uint32_t chars = rd32(bytes, sec_off + 36, &okr);
    s.executable = (chars & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
    if (!okr) break;
    sections.push_back(s);
  }
  ok = true;
  (void)resource_rva;
  // 把资源 RVA 暂存到 image_base 之外是不合适的；调用方通过单独函数获取。
  resource_rva_ = resource_rva;
  return true;
}

std::optional<uint32_t> PeImage::rva_to_offset(uint32_t rva) const {
  for (const auto& s : sections) {
    uint32_t span = std::max(s.vsize, s.raw_size);
    if (rva >= s.rva && rva - s.rva < span) {
      uint32_t off = s.raw_ptr + (rva - s.rva);
      if (off < bytes.size()) return off;
      return std::nullopt;
    }
  }
  // 头部区域：RVA == 文件偏移
  if (rva < bytes.size() && (sections.empty() || rva < sections.front().rva)) return rva;
  return std::nullopt;
}

std::optional<uint32_t> PeImage::offset_to_rva(uint32_t off) const {
  for (const auto& s : sections) {
    if (off >= s.raw_ptr && off - s.raw_ptr < s.raw_size) return s.rva + (off - s.raw_ptr);
  }
  return std::nullopt;
}

bool parse_version_string(const std::string& s, int* major, int* minor, int* patch, int* build) {
  std::string t = trim(s);
  // 去掉可能的产品前缀，例如 "wow-12.1.5.70783" / "Version 3.3.5a"
  auto parts = split(t, '.');
  std::vector<int> nums;
  for (auto& p : parts) {
    std::string digits;
    for (char c : p) { if (std::isdigit(static_cast<unsigned char>(c))) digits.push_back(c); else break; }
    if (digits.empty()) { nums.clear(); continue; }
    long long v = 0;
    try { v = std::stoll(digits); } catch (...) { return false; }
    if (v > 10000000) return false;
    nums.push_back(static_cast<int>(v));
  }
  if (nums.empty() || nums.size() > 4) return false;
  if (nums.size() == 1) {  // 单独的 build 号
    if (build) *build = nums[0];
    if (major) *major = 0;
    if (minor) *minor = 0;
    if (patch) *patch = 0;
    return true;
  }
  if (major) *major = nums[0];
  if (minor) *minor = nums.size() > 1 ? nums[1] : 0;
  if (patch) *patch = nums.size() > 2 ? nums[2] : 0;
  if (build) *build = nums.size() > 3 ? nums[3] : 0;
  return true;
}

bool parse_build_info(const std::string& text, ClientInfo* out, std::string* err) {
  if (!out) return false;
  std::vector<std::string> lines = split(replace_all(text, "\r\n", "\n"), '\n');
  std::vector<std::string> cols;
  size_t header_line = 0;
  bool found = false;
  for (size_t i = 0; i < lines.size(); ++i) {
    if (lines[i].find('|') == std::string::npos) continue;
    cols = split(lines[i], '|');
    header_line = i;
    found = true;
    break;
  }
  if (!found) { if (err) *err = ".build.info 没有表头"; return false; }
  for (auto& c : cols) {
    size_t bang = c.find('!');
    if (bang != std::string::npos) c = c.substr(0, bang);
    c = trim(c);
    if (c.size() >= 2 && static_cast<unsigned char>(c[0]) == 0xEF) c.erase(0, 3);
  }
  auto col = [&](const std::string& name) -> int {
    for (size_t i = 0; i < cols.size(); ++i) if (iequals(cols[i], name)) return static_cast<int>(i);
    return -1;
  };
  int i_version = col("Version"), i_product = col("Product"), i_branch = col("Branch");
  int i_active = col("Active"), i_bkey = col("Build Key"), i_ckey = col("CDN Key");

  // 优先 Active=1 的行
  std::vector<std::string> row;
  for (size_t i = header_line + 1; i < lines.size(); ++i) {
    if (trim(lines[i]).empty()) continue;
    auto r = split(lines[i], '|');
    if (r.empty()) continue;
    bool active = true;
    if (i_active >= 0 && static_cast<size_t>(i_active) < r.size()) active = trim(r[i_active]) != "0";
    if (active) { row = r; break; }
    if (row.empty()) row = r;
  }
  if (row.empty()) { if (err) *err = ".build.info 没有数据行"; return false; }
  auto get = [&](int idx) -> std::string { return (idx >= 0 && static_cast<size_t>(idx) < row.size()) ? trim(row[idx]) : std::string(); };
  out->version_string = get(i_version);
  out->product = get(i_product);
  out->branch = get(i_branch);
  out->build_key = get(i_bkey);
  out->cdn_key = get(i_ckey);
  if (!out->version_string.empty()) parse_version_string(out->version_string, &out->major, &out->minor, &out->patch, &out->build);
  return true;
}

// 读取 PE 导入表里的 DLL 名。私服客户端常常把整个游戏包一层 "Wow_loader.dll"，
// 这类加载层 DLL 是必须一起分析的（hook 点可能在 DLL 里而不是 exe 里）。
std::vector<std::string> read_import_dlls(const PeImage& pe) {
  std::vector<std::string> out;
  const auto& b = pe.bytes;
  auto u32 = [&](size_t o) -> uint32_t {
    if (o + 4 > b.size()) return 0;
    return static_cast<uint32_t>(b[o]) | (static_cast<uint32_t>(b[o + 1]) << 8) |
           (static_cast<uint32_t>(b[o + 2]) << 16) | (static_cast<uint32_t>(b[o + 3]) << 24);
  };
  size_t pe_off = b.size() > 0x40 ? u32(0x3C) : 0;
  if (pe_off + 24 > b.size() || u32(pe_off) != 0x00004550u) return out;
  uint16_t opt_size = static_cast<uint16_t>(b[pe_off + 20] | (b[pe_off + 21] << 8));
  size_t opt = pe_off + 24;
  uint16_t magic = static_cast<uint16_t>(b[opt] | (b[opt + 1] << 8));
  size_t dir_off = magic == 0x10B ? opt + 96 : opt + 112;
  uint32_t num_dirs = u32(magic == 0x10B ? opt + 92 : opt + 108);
  if (num_dirs < 2 || dir_off + 16 > b.size()) return out;
  uint32_t imp_rva = u32(dir_off + 8), imp_size = u32(dir_off + 12);
  auto io = pe.rva_to_offset(imp_rva);
  if (!io) return out;
  for (size_t o = *io; o + 20 <= b.size() && o + 20 <= *io + imp_size; o += 20) {
    uint32_t name_rva = u32(o + 12);
    if (!name_rva) break;
    auto no = pe.rva_to_offset(name_rva);
    if (!no) continue;
    std::string name;
    for (size_t p = *no; p < b.size() && b[p] && name.size() < 128; ++p) name.push_back(static_cast<char>(b[p]));
    if (!name.empty()) out.push_back(name);
  }
  return out;
}

bool parse_pe_metadata(const std::vector<uint8_t>& bytes, ClientInfo* out, std::string* err) {
  PeImage pe;
  if (!pe.load(bytes, err)) return false;
  out->companion_dlls = read_import_dlls(pe);
  switch (pe.machine) {
    case 0x014C: out->arch = "x86"; break;
    case 0x8664: out->arch = "x64"; break;
    case 0xAA64: out->arch = "arm64"; break;
    case 0x01C4: out->arch = "arm"; break;
    default: out->arch = "unknown(0x" + to_hex(pe.machine, 4) + ")"; break;
  }
  bool got = false;
  if (pe.resource_rva_ != 0) got = read_version_resource(pe, pe.resource_rva_, out);
  // 资源目录被改写时，scan_version_signature 仍能从固定字段拿到架构/版本；
  // StringFileInfo 只在正常资源树中读取，避免全文件误匹配。
  if (!got) got = scan_version_signature(bytes, out);
  return got;
}

std::string detect_storage_layout(const std::string& game_dir, std::string* data_dir) {
  std::string data = join_path(game_dir, "Data");
  if (!dir_exists(data)) {
    // 有些客户端把 Data 放在子目录（不写死目录名，扫描一层）
    std::error_code ec;
    for (fs::directory_iterator it(game_dir, ec), end; !ec && it != end; it.increment(ec)) {
      if (it->is_directory(ec)) {
        std::string candidate = join_path(normalize_path(it->path().string()), "Data");
        if (dir_exists(candidate)) { data = candidate; break; }
      }
    }
  }
  if (!dir_exists(data)) {
    // 私服常见布局：D:/Midnight Open Beta/_midnight_/Wow.exe，Data 在父目录。
    // 向上找两层，仍然不写死任何目录名。
    std::string p = parent_path(game_dir);
    for (int i = 0; i < 2 && !p.empty(); ++i) {
      std::string candidate = join_path(p, "Data");
      if (dir_exists(candidate)) { data = candidate; break; }
      p = parent_path(p);
    }
  }
  if (data_dir) *data_dir = data;
  bool casc = dir_exists(join_path(data, "data")) || dir_exists(join_path(data, "indices")) || dir_exists(join_path(data, "config"));
  bool mpq = false;
  std::error_code ec;
  if (dir_exists(data)) {
    for (fs::recursive_directory_iterator it(data, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
      std::string ext = to_upper(file_extension(it->path().string()));
      if (ext == ".MPQ" || ext == ".MPQ2") { mpq = true; break; }
      if (ext == ".IDX" || ext == ".BLOB") casc = true;
    }
  }
  if (casc && mpq) return "hybrid";
  if (casc) return "casc";
  if (mpq) return "mpq";
  return "unknown";
}

void detect_server_settings(const std::string& game_dir, ClientInfo* out) {
  std::string cfg;
  if (read_text_file(join_path(game_dir, "WTF/Config.wtf"), &cfg, nullptr)) {
    for (const auto& line : split(replace_all(cfg, "\r\n", "\n"), '\n')) {
      std::string t = trim(line);
      if (iequals(t.substr(0, 3), "SET")) {
        auto kv = split_ws(t.substr(3));
        if (kv.size() >= 2 && iequals(kv[0], "portal")) {
          out->portal = trim(kv[1]);
          size_t q = out->portal.find('"');
          if (q != std::string::npos) {
            size_t e = out->portal.rfind('"');
            out->portal = e > q ? out->portal.substr(q + 1, e - q - 1) : out->portal.substr(q + 1);
          }
        }
      }
    }
  }
  for (const std::string& p : {join_path(game_dir, "realmlist.wtf"), join_path(game_dir, "Data/realmlist.wtf")}) {
    std::string r;
    if (read_text_file(p, &r, nullptr)) { out->realmlist = trim(r); break; }
  }
}

std::vector<std::string> discover_client_exes(const std::string& root, int max_depth) {
  std::vector<std::string> out;
  std::error_code ec;
  if (!dir_exists(root)) return out;
  for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
    if (it.depth() >= max_depth) { it.disable_recursion_pending(); continue; }
    if (!it->is_regular_file(ec)) continue;
    std::string ext = to_upper(file_extension(it->path().string()));
    if (ext != ".EXE") continue;
    std::string name = to_lower(file_name(it->path().string()));
    if (starts_with(name, "wow") || starts_with(name, "world of warcraft")) out.push_back(normalize_path(it->path().string()));
  }
  std::sort(out.begin(), out.end());
  return out;
}

ClientInfo detect_client(const std::string& path, Diagnostics* diag, std::vector<uint8_t>* exe_bytes_out) {
  ClientInfo ci;
  // Windows 盘符路径（D:/...）在 Linux 上做 dry-run 校验时不能再被 fs::absolute 拼到 cwd 上。
  std::string input = is_absolute_path(path) ? normalize_path(path) : absolute_path(path);
  std::string exe;
  if (file_exists(input) && iequals(file_extension(input), ".exe")) exe = input;
  else if (dir_exists(input)) {
    auto exes = discover_client_exes(input);
    if (!exes.empty()) exe = exes.front();
  }
  if (exe.empty()) {
    if (diag) diag->warn("detect", "未在 " + input + " 找到 wow*.exe；仅能使用配置中显式指定的 exe");
    ci.game_dir = input;
  } else {
    ci.exe_path = exe;
    ci.game_dir = parent_path(exe);
    ci.valid = true;
    std::vector<uint8_t> bytes;
    std::string err;
    if (read_binary_file(exe, &bytes, &err)) {
      if (exe_bytes_out) *exe_bytes_out = bytes;
      ClientInfo pe_info;
      std::string pe_err;
      if (parse_pe_metadata(bytes, &pe_info, &pe_err)) {
        ci.major = pe_info.major; ci.minor = pe_info.minor; ci.patch = pe_info.patch; ci.build = pe_info.build;
        ci.version_string = pe_info.version_string; ci.arch = pe_info.arch;
        ci.companion_dlls = pe_info.companion_dlls;
      } else if (diag) diag->warn("detect", "PE 版本资源读取失败: " + pe_err + "（不影响启动）");
      // 私服的 "Wow_loader.dll" 这类加载层：exe 只是壳，特征扫描要覆盖到 DLL。
      for (const auto& dll : ci.companion_dlls) {
        std::string lp = join_path(ci.game_dir, dll);
        if (file_exists(lp)) ci.notes.push_back("检测到加载层 DLL: " + dll +
            " — 若 hook 点在 DLL 里，请对它单独运行 wowmod discover/scan（--exe 指向该 DLL）");
      }
    } else if (diag) diag->warn("detect", err);
  }

  // .build.info 覆盖 exe 资源（更准确，且老客户端可能没有版本资源）
  std::vector<std::string> candidates = {
      join_path(ci.game_dir, ".build.info"),
      join_path(parent_path(ci.game_dir), ".build.info"),
      join_path(parent_path(parent_path(ci.game_dir)), ".build.info"),
  };
  for (const auto& p : candidates) {
    std::string text;
    if (!read_text_file(p, &text, nullptr)) continue;
    ClientInfo bi;
    std::string berr;
    if (parse_build_info(text, &bi, &berr)) {
      if (!bi.version_string.empty()) {
        ci.version_string = bi.version_string;
        ci.major = bi.major; ci.minor = bi.minor; ci.patch = bi.patch; ci.build = bi.build;
      }
      if (!bi.product.empty()) ci.product = bi.product;
      if (!bi.branch.empty()) ci.branch = bi.branch;
      ci.build_key = bi.build_key;
      ci.cdn_key = bi.cdn_key;
      ci.notes.push_back("版本来自 " + p);
      break;
    } else if (diag) diag->warn("detect", p + ": " + berr);
  }
  if (ci.version_string.empty()) {
    ci.version_string = "未知版本";
    ci.notes.push_back("未能读取版本号 —— 加载器不依赖版本号，所有功能照常可用");
  } else if (ci.build == 0) {
    ci.notes.push_back("版本串里没有 build 号（例如只写了 12.0.7）—— 不影响任何功能；可在配置的 client.build 里补一个供 when 过滤使用");
  }
  ci.storage = detect_storage_layout(ci.game_dir, &ci.data_dir);
  detect_server_settings(ci.game_dir, &ci);
  if (ci.storage == "unknown") ci.notes.push_back("未探测到 CASC/MPQ 目录；通用 VFS 覆盖仍然生效");
  ci.notes.push_back("无任何版本白名单：本客户端被视为【已支持】");
  return ci;
}

Json ClientInfo::to_json() const {
  Json j = Json::make_object();
  j.set("valid", Json::make_bool(valid));
  j.set("exe", Json::make_string(exe_path));
  j.set("game_dir", Json::make_string(game_dir));
  j.set("data_dir", Json::make_string(data_dir));
  j.set("version", Json::make_string(version_string));
  j.set("major", Json::make_number(major));
  j.set("minor", Json::make_number(minor));
  j.set("patch", Json::make_number(patch));
  j.set("build", Json::make_number(build));
  j.set("product", Json::make_string(product));
  j.set("branch", Json::make_string(branch));
  j.set("arch", Json::make_string(arch));
  j.set("storage", Json::make_string(storage));
  j.set("portal", Json::make_string(portal));
  j.set("supported", Json::make_bool(true));
  Json dll_arr = Json::make_array();
  for (const auto& d : companion_dlls) dll_arr.push(Json::make_string(d));
  j.set("companionDlls", dll_arr);
  Json notes_arr = Json::make_array();
  for (const auto& n : notes) notes_arr.push(Json::make_string(n));
  j.set("notes", notes_arr);
  return j;
}

void apply_display_overrides(ClientInfo* ci, const std::string& version, int build) {
  if (!ci) return;
  if (!version.empty()) {
    ci->version_string = trim(version);
    parse_version_string(ci->version_string, &ci->major, &ci->minor, &ci->patch, &ci->build);
    ci->notes.push_back("版本展示来自配置 client.version（仅用于展示）");
  }
  if (build > 0) {
    ci->build = build;
    ci->notes.push_back("build 来自配置 client.build（供 when 过滤使用，不是支持性判断）");
  }
}

std::string ClientInfo::display() const {
  std::ostringstream os;
  os << "版本: " << version_string << " (build " << (build > 0 ? std::to_string(build) : "未知") << ")\n"
     << "架构: " << arch << " | 存储: " << storage << " | 产品: " << (product.empty() ? "-" : product) << "\n"
     << "exe: " << (exe_path.empty() ? "(未指定)" : exe_path) << "\n"
     << "游戏目录: " << game_dir << "\n"
     << "Data: " << data_dir << "\n"
     << "portal: " << (portal.empty() ? "(未设置)" : portal) << "\n";
  if (!companion_dlls.empty()) os << "加载层 DLL: " << join(companion_dlls, ", ") << "\n";
  os << "支持状态: 已支持（无版本白名单）";
  return os.str();
}

}  // namespace wowmod
