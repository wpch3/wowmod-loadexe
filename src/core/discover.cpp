// SPDX-License-Identifier: MIT
#include "wowmod/discover.hpp"

#include <algorithm>
#include <cctype>
#include <utility>
#include <sstream>

#include "wowmod/json.hpp"
#include "wowmod/util.hpp"
#include "wowmod/version.hpp"

namespace wowmod {

namespace {

std::string pattern_text(const std::vector<int>& bytes) {
  std::string out;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i) out += ' ';
    if (bytes[i] < 0) out += "??";
    else {
      static const char* hex = "0123456789ABCDEF";
      out += hex[(bytes[i] >> 4) & 0xF];
      out += hex[bytes[i] & 0xF];
    }
  }
  return out;
}

size_t fixed_count(const std::vector<int>& bytes) {
  return static_cast<size_t>(std::count_if(bytes.begin(), bytes.end(), [](int b) { return b >= 0; }));
}

// 找出"跨 build 最容易变"的位置：相对跳转/调用的 rel32、RIP 相对寻址的 disp32。
std::vector<size_t> volatile_positions(const std::vector<int>& bytes) {
  std::vector<size_t> out;
  auto mark = [&](size_t start, size_t len) {
    for (size_t i = start; i < start + len && i < bytes.size(); ++i)
      if (bytes[i] >= 0) out.push_back(i);
  };
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (bytes[i] == 0xE8 || bytes[i] == 0xE9) { mark(i + 1, 4); continue; }
    if (bytes[i] == 0x0F && i + 1 < bytes.size() && bytes[i + 1] >= 0 &&
        (bytes[i + 1] & 0xF0) == 0x80) { mark(i + 2, 4); continue; }
    // REX + 8D + ModRM(mod=00, rm=101) => RIP 相对
    if (i + 2 < bytes.size() && bytes[i] >= 0x40 && bytes[i] <= 0x4F && bytes[i + 1] == 0x8D &&
        bytes[i + 2] >= 0 && (static_cast<int>(bytes[i + 2]) & 0xC7) == 0x05) { mark(i + 3, 4); continue; }
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

struct MismatchHit {
  size_t offset = 0;
  std::vector<size_t> positions;  // 与原始特征不同的固定字节位置
};

// 在一次扫描里找出"最多差 max_k 个固定字节"的所有位置，并记录具体是哪些位置不同。
std::vector<MismatchHit> mismatch_scan(const std::vector<uint8_t>& hay, const std::vector<int>& bytes,
                                       const std::vector<std::pair<size_t, size_t>>& ranges, size_t max_k,
                                       size_t cap) {
  std::vector<MismatchHit> out;
  const size_t m = bytes.size();
  for (const auto& rg : ranges) {
    if (rg.second < m || rg.first >= hay.size()) continue;
    size_t end = std::min(rg.first + rg.second, hay.size()) - m + 1;
    for (size_t off = rg.first; off < end; ++off) {
      MismatchHit hit;
      hit.offset = off;
      for (size_t i = 0; i < m; ++i) {
        if (bytes[i] < 0) continue;
        if (hay[off + i] != static_cast<uint8_t>(bytes[i])) {
          hit.positions.push_back(i);
          if (hit.positions.size() > max_k) break;
        }
      }
      if (hit.positions.size() <= max_k) {
        out.push_back(std::move(hit));
        if (out.size() >= cap) return out;
      }
    }
  }
  return out;
}

bool subset_of(const std::vector<size_t>& small, const std::vector<size_t>& big) {
  return std::all_of(small.begin(), small.end(), [&](size_t p) {
    return std::find(big.begin(), big.end(), p) != big.end();
  });
}

std::vector<std::pair<size_t, size_t>> pe_ranges(const PeImage& pe, size_t file_size) {
  std::vector<std::pair<size_t, size_t>> out;
  for (const auto& sec : pe.sections) {
    if (!sec.executable || sec.raw_size == 0 || sec.raw_ptr >= file_size) continue;
    out.emplace_back(sec.raw_ptr, std::min<size_t>(sec.raw_size, file_size - sec.raw_ptr));
  }
  return out;
}

std::vector<size_t> unique_order(std::vector<size_t> order, size_t n) {
  order.erase(std::remove_if(order.begin(), order.end(), [n](size_t i) { return i >= n; }), order.end());
  std::vector<size_t> out;
  for (size_t i : order) if (std::find(out.begin(), out.end(), i) == out.end()) out.push_back(i);
  return out;
}

}  // namespace

size_t count_matches(const Pattern& p, const std::vector<uint8_t>& haystack, size_t cap, std::vector<size_t>* offsets) {
  if (offsets) offsets->clear();
  if (!p.valid() || cap == 0) return 0;
  size_t count = 0, pos = 0;
  while (count < cap) {
    auto f = p.find(haystack, pos);
    if (!f) break;
    if (offsets) offsets->push_back(*f);
    ++count;
    pos = *f + 1;
  }
  return count;
}

AdaptResult relax_pattern(const std::string& text, const std::vector<uint8_t>& exe, size_t min_fixed, std::string* err) {
  AdaptResult r;
  r.source_pattern = text;
  if (err) err->clear();
  Pattern base = Pattern::parse(text, err);
  if (!base.valid()) {
    r.reason = "特征解析失败: " + (err ? *err : "空特征");
    return r;
  }
  if (exe.empty()) { r.reason = "exe 字节为空"; return r; }

  const size_t n = base.bytes.size();
  const size_t base_fixed = fixed_count(base.bytes);
  if (base_fixed < 4) { r.reason = "固定字节太少（<4），放宽后没有意义，请提供更长的特征"; return r; }
  const size_t keep = std::min(min_fixed, std::max<size_t>(4, base_fixed / 2));

  PeImage pe;
  std::string peerr;
  bool have_pe = pe.load(exe, &peerr);
  if (have_pe) r.arch = pe.machine == 0x8664 ? "x64" : pe.machine == 0xAA64 ? "arm64" : pe.machine == 0x14C ? "x86" : "unknown";

  std::vector<size_t> offs;
  size_t original_matches = count_matches(base, exe, 2, &offs);
  r.warning = (original_matches == 0);
  r.match_count = original_matches;

  // 把一次"唯一匹配"包装成结果
  auto make_result = [&](const std::vector<int>& bytes, size_t offset, const std::string& why) -> AdaptResult {
    AdaptResult a;
    a.ok = true;
    a.source_pattern = text;
    a.pattern = pattern_text(bytes);
    a.fixed_bytes = fixed_count(bytes);
    a.wildcard_bytes = n - a.fixed_bytes;
    a.match_count = 1;
    a.file_offset = offset;
    a.warning = r.warning;
    a.arch = r.arch;
    a.reason = why;
    if (have_pe) {
      auto rva = pe.offset_to_rva(static_cast<uint32_t>(offset));
      if (rva) {
        a.rva = *rva;
        for (const auto& sec : pe.sections) {
          if (offset >= sec.raw_ptr && offset - sec.raw_ptr < sec.raw_size) { a.executable = sec.executable; break; }
        }
      }
    }
    return a;
  };

  if (original_matches == 1) return make_result(base.bytes, offs[0], "原始特征已经唯一匹配，无需放宽");

  // ---- 主算法：差异引导，寻找【最小】的通配集合 ----
  // 一次扫描记录"最多差 max_k 个固定字节"的位置及具体差异位置；
  // 若把某个候选的差异位置全改成 ?? 后，只有它自己能匹配，就得到了最紧的特征。
  const size_t max_k = base_fixed - keep;
  std::vector<std::pair<size_t, size_t>> ranges = have_pe ? pe_ranges(pe, exe.size())
                                                         : std::vector<std::pair<size_t, size_t>>{};
  bool restricted = !ranges.empty();
  if (!restricted) ranges.emplace_back(0, exe.size());
  std::vector<MismatchHit> hits = mismatch_scan(exe, base.bytes, ranges, max_k, 512);
  if (hits.empty() && restricted) {
    // 可执行节区里没有近似匹配时，退回整文件再扫一次
    ranges.clear();
    ranges.emplace_back(0, exe.size());
    hits = mismatch_scan(exe, base.bytes, ranges, max_k, 512);
  }
  std::stable_sort(hits.begin(), hits.end(), [](const MismatchHit& a, const MismatchHit& b) {
    return a.positions.size() < b.positions.size();
  });

  AdaptResult best;
  for (const auto& hit : hits) {
    if (hit.positions.empty()) continue;  // 原样匹配已在上面处理
    if (best.ok && hit.positions.size() > best.wildcard_bytes) break;
    // 统计"差异集合是 hit.positions 子集"的候选数量（无需重新扫整个 exe）
    size_t qualifying = 0;
    for (const auto& other : hits) {
      if (subset_of(other.positions, hit.positions)) ++qualifying;
      if (qualifying > 1) break;
    }
    if (qualifying != 1) continue;
    std::vector<int> bytes = base.bytes;
    for (size_t p : hit.positions) bytes[p] = -1;
    if (fixed_count(bytes) < keep) continue;
    Pattern candidate;
    candidate.bytes = bytes;
    candidate.source = pattern_text(bytes);
    std::vector<size_t> found;
    if (count_matches(candidate, exe, 2, &found) != 1) continue;
    std::string why = "定位到 " + std::to_string(hit.positions.size()) + " 个跨版本差异字节并放宽，得到唯一匹配";
    if (hit.positions.size() * 3 > base_fixed) {
      why += "；⚠ 放宽了超过三分之一的固定字节，跨版本跨度可能过大，建议改用更贴近 12.x 的起点特征";
    }
    AdaptResult cand = make_result(bytes, found[0], why);
    if (!best.ok || cand.fixed_bytes > best.fixed_bytes) best = cand;
  }

  // ---- 兜底：差异引导失败时，按"易变字节 -> 尾部 -> 头部"逐步放宽 ----
  if (!best.ok) {
    std::vector<size_t> vol = volatile_positions(base.bytes);
    std::vector<size_t> all_fixed;
    for (size_t i = 0; i < n; ++i) if (base.bytes[i] >= 0) all_fixed.push_back(i);
    std::vector<size_t> reverse = all_fixed;
    std::reverse(reverse.begin(), reverse.end());
    std::vector<size_t> o1 = vol;
    o1.insert(o1.end(), reverse.begin(), reverse.end());
    std::vector<std::vector<size_t>> orders = {
        unique_order(std::move(o1), n), unique_order(reverse, n), unique_order(all_fixed, n)};
    for (const auto& order : orders) {
      std::vector<int> bytes = base.bytes;
      for (size_t k = 0; k < order.size(); ++k) {
        size_t idx = order[k];
        if (bytes[idx] >= 0) bytes[idx] = -1;
        if (fixed_count(bytes) < keep) break;
        Pattern candidate;
        candidate.bytes = bytes;
        candidate.source = pattern_text(bytes);
        std::vector<size_t> found;
        if (count_matches(candidate, exe, 2, &found) != 1) continue;
        AdaptResult cand = make_result(bytes, found[0], "已放宽 " + std::to_string(k + 1) + " 个字节得到唯一匹配");
        if (!best.ok || cand.fixed_bytes > best.fixed_bytes) best = cand;
        break;
      }
    }
  }

  if (best.ok) {
    if (best.warning) best.reason += "；⚠ 原始特征在本 exe 上 0 处匹配，放宽后可能命中了别的函数，务必用调试器核实";
    else if (!best.executable) best.reason += "；⚠ 命中位置不在可执行节区，请核对";
    return best;
  }
  r.ok = false;
  r.reason = "无法在保留至少 " + std::to_string(keep) + " 个固定字节的前提下得到唯一匹配（原始特征 " +
             (original_matches >= 2 ? "匹配 " + std::to_string(original_matches) + "+ 处" : "0 处") +
             "）。请提供更长、更贴近该版本家族的特征，或用调试器重新定位函数入口";
  return r;
}

Json AdaptResult::to_json() const {
  Json j = Json::make_object();
  j.set("ok", Json::make_bool(ok));
  j.set("pattern", Json::make_string(pattern));
  j.set("sourcePattern", Json::make_string(source_pattern));
  j.set("fixedBytes", Json::make_number(static_cast<double>(fixed_bytes)));
  j.set("wildcardBytes", Json::make_number(static_cast<double>(wildcard_bytes)));
  j.set("matches", Json::make_number(static_cast<double>(match_count)));
  j.set("fileOffset", Json::make_number(static_cast<double>(file_offset)));
  j.set("rva", Json::make_number(static_cast<double>(rva)));
  j.set("executable", Json::make_bool(executable));
  j.set("warning", Json::make_bool(warning));
  j.set("arch", Json::make_string(arch));
  j.set("reason", Json::make_string(reason));
  return j;
}

AdaptFileResult adapt_pattern_file(const std::string& exe_path, const std::string& pattern_text_in,
                                   const std::string& out_path, const std::string& name,
                                   const std::string& id_register, std::string* err) {
  AdaptFileResult out;
  if (err) err->clear();
  std::vector<uint8_t> bytes;
  std::string ferr;
  if (!read_binary_file(exe_path, &bytes, &ferr)) {
    out.reason = ferr;
    if (err) *err = ferr;
    return out;
  }
  out.adapted = relax_pattern(pattern_text_in, bytes, 8, &ferr);
  if (!out.adapted.ok) {
    out.reason = out.adapted.reason;
    if (err) *err = out.reason;
    return out;
  }

  std::string werr;
  if (!write_pattern_descriptor(out_path, name, out.adapted.pattern,
                                out.adapted.arch.empty() ? "x64" : out.adapted.arch,
                                id_register.empty() ? "rdx" : id_register,
                                "由 wowmod adapt 自动放宽得到；请用调试器确认该函数返回值是路径指针", &werr)) {
    out.reason = werr;
    if (err) *err = werr;
    return out;
  }
  out.ok = true;
  out.out_path = out_path;
  out.reason = "已写入 " + out_path + "；把它加入 hooks.patterns 后运行 wowmod plan 验证";
  return out;
}

Json AdaptFileResult::to_json() const {
  Json j = Json::make_object();
  j.set("ok", Json::make_bool(ok));
  j.set("out", Json::make_string(out_path));
  j.set("reason", Json::make_string(reason));
  j.set("adapt", adapted.to_json());
  return j;
}


bool write_pattern_descriptor(const std::string& out_path, const std::string& name,
                              const std::string& pattern, const std::string& arch,
                              const std::string& id_register, const std::string& note,
                              std::string* err) {
  if (err) err->clear();
  Json doc;
  std::string existing;
  if (read_text_file(out_path, &existing, nullptr)) {
    std::string perr;
    doc = Json::parse(existing, &perr);
    if (!perr.empty()) doc = Json::make_object();
  }
  if (doc.type != Json::Type::Object) doc = Json::make_object();
  Json arr = doc.at("patterns");
  if (arr.type != Json::Type::Array) arr = Json::make_array();
  else {
    Json kept = Json::make_array();
    for (const auto& item : arr.as_array()) if (item.at("name").as_string() != name) kept.push(item);
    arr = kept;
  }
  Json d = Json::make_object();
  d.set("name", Json::make_string(name));
  d.set("kind", Json::make_string("fileId"));
  d.set("arch", Json::make_string(arch.empty() ? "x64" : arch));
  d.set("pattern", Json::make_string(pattern));
  d.set("offset", Json::make_number(0));
  d.set("idRegister", Json::make_string(id_register.empty() ? "rdx" : id_register));
  d.set("result", Json::make_string("rax=pathPtr"));
  d.set("priority", Json::make_number(10));
  d.set("note", Json::make_string(note));
  arr.push(d);
  doc.set("patterns", arr);
  std::string werr;
  if (!write_text_file(out_path, doc.dump(2) + "\n", &werr)) {
    if (err) *err = werr;
    return false;
  }
  return true;
}

std::vector<std::string> default_anchors() {
  return {
      "DBFilesClient\\", "Interface\\AddOns\\", "World\\Model\\", "World\\Textures\\",
      "realmlist.wtf", "Unable to open", "FileDataID", "CascOpen", "patch-",
      "World of Warcraft usage", "Interface\\FrameXML\\", ".build.info"};
}

namespace {

uint32_t read32(const std::vector<uint8_t>& b, size_t off) {
  return static_cast<uint32_t>(b[off]) | (static_cast<uint32_t>(b[off + 1]) << 8) |
         (static_cast<uint32_t>(b[off + 2]) << 16) | (static_cast<uint32_t>(b[off + 3]) << 24);
}

// 大小写不敏感地在 buffer 中找 ASCII 串
std::vector<size_t> find_string(const std::vector<uint8_t>& b, const std::string& needle) {
  std::vector<size_t> out;
  if (needle.empty() || needle.size() > b.size()) return out;
  std::string lower = to_lower(needle);
  for (size_t i = 0; i + needle.size() <= b.size(); ++i) {
    bool ok = true;
    for (size_t k = 0; k < needle.size(); ++k) {
      unsigned char c = b[i + k];
      if (static_cast<char>(std::tolower(c)) != lower[k]) { ok = false; break; }
    }
    if (ok) out.push_back(i);
  }
  return out;
}

// 把一段机器码变成建议特征：相对跳转/调用的 rel32、RIP 相对 disp32 全部通配
std::string suggest_pattern(const std::vector<uint8_t>& exe, size_t start, size_t len, size_t* fixed_out) {
  static const char* hx = "0123456789ABCDEF";
  std::vector<int> bytes;
  for (size_t i = 0; i < len && start + i < exe.size(); ++i)
    bytes.push_back(static_cast<int>(exe[start + i]));
  auto wild = [&](size_t from, size_t count) {
    for (size_t i = from; i < from + count && i < bytes.size(); ++i) bytes[i] = -1;
  };
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (bytes[i] == 0xE8 || bytes[i] == 0xE9) { wild(i + 1, 4); continue; }
    if (bytes[i] == 0x0F && i + 1 < bytes.size() &&
        (static_cast<int>(bytes[i + 1]) & 0xF0) == 0x80) { wild(i + 2, 4); continue; }
    if (i + 2 < bytes.size() && bytes[i] >= 0x40 && bytes[i] <= 0x4F && bytes[i + 1] == 0x8D &&
        bytes[i + 2] >= 0 && (bytes[i + 2] & 0xC7) == 0x05) { wild(i + 3, 4); continue; }
  }
  size_t fixed = 0;
  std::string out;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i) out += ' ';
    if (bytes[i] < 0) out += "??";
    else { out += hx[(bytes[i] >> 4) & 0xF]; out += hx[bytes[i] & 0xF]; ++fixed; }
  }
  if (fixed_out) *fixed_out = fixed;
  return out;
}

}  // namespace

DiscoveryReport discover_hook_points(const std::vector<uint8_t>& exe, const std::vector<std::string>& anchors) {
  DiscoveryReport rep;
  rep.anchors = anchors;
  rep.note = "候选由字符串引用自动推导，不等于目标函数；请用调试器/wowmod scan 核实，唯一匹配也不代表语义正确";
  if (exe.empty()) { rep.note = "exe 字节为空"; return rep; }
  PeImage pe;
  std::string peerr;
  rep.pe = pe.load(exe, &peerr);
  if (rep.pe) rep.arch = pe.machine == 0x8664 ? "x64" : pe.machine == 0xAA64 ? "arm64"
                                              : pe.machine == 0x14C ? "x86" : "unknown";

  // 1) 锚点字符串 -> RVA
  struct AnchorRva { std::string text; uint32_t rva; };
  std::vector<AnchorRva> found;
  for (const auto& a : anchors) {
    auto offsets = find_string(exe, a);
    if (offsets.empty()) continue;
    rep.anchors_found.push_back(a);
    for (size_t off : offsets) {
      uint32_t rva = 0;
      if (rep.pe) { auto r = pe.offset_to_rva(static_cast<uint32_t>(off)); if (!r) continue; rva = *r; }
      found.push_back({a, rva});
    }
  }

  // 2) 可执行节区里找 RIP 相对 LEA 引用（REX + 8D + ModRM(mod=00,rm=101)）
  auto ranges = rep.pe ? pe_ranges(pe, exe.size()) : std::vector<std::pair<size_t, size_t>>{};
  if (ranges.empty()) ranges.emplace_back(0, exe.size());
  std::vector<std::pair<size_t, std::string>> xrefs;  // (指令文件偏移, 锚点名)
  size_t seen = 0;
  for (const auto& rg : ranges) {
    if (rg.first + 7 >= exe.size()) continue;
    size_t end = std::min(rg.first + rg.second, exe.size()) - 7;
    for (size_t off = rg.first; off < end; ++off) {
      uint8_t rex = exe[off];
      if (rex < 0x40 || rex > 0x4F || exe[off + 1] != 0x8D) continue;
      uint8_t modrm = exe[off + 2];
      if ((modrm & 0xC7) != 0x05) continue;  // RIP 相对
      uint32_t instr_rva = 0;
      if (rep.pe) { auto r = pe.offset_to_rva(static_cast<uint32_t>(off)); if (!r) continue; instr_rva = *r; }
      int32_t disp = static_cast<int32_t>(read32(exe, off + 3));
      uint32_t target = static_cast<uint32_t>(static_cast<int64_t>(instr_rva) + 7 + disp);
      for (const auto& a : found) {
        // 允许指向字符串开头附近（编译器常引用字符串前几个字节/结构体里的指针）
        if (target >= a.rva && target - a.rva <= 24) {
          xrefs.emplace_back(off, a.text);
          ++seen;
          break;
        }
      }
      if (seen >= 400) break;
    }
    if (seen >= 400) break;
  }

  // 3) 为每个 xref 生成候选特征，优先保留"唯一匹配"且固定字节多的
  for (const auto& xr : xrefs) {
    for (size_t len : {32u, 48u}) {
      size_t fixed = 0;
      std::string pat = suggest_pattern(exe, xr.first, len, &fixed);
      if (fixed < 8) continue;
      std::string perr;
      Pattern p = Pattern::parse(pat, &perr);
      if (!p.valid()) continue;
      size_t matches = count_matches(p, exe, 3);
      HookCandidate c;
      c.anchor = xr.second;
      c.file_offset = xr.first;
      c.pattern = pat;
      c.fixed_bytes = fixed;
      c.unique_matches = matches;
      c.executable = true;
      if (rep.pe) { auto r = pe.offset_to_rva(static_cast<uint32_t>(xr.first)); if (r) c.code_rva = *r; }
      c.reason = matches == 1 ? "唯一匹配，可作为 adapt/plan 的起点（仍需核实函数语义）"
                              : "匹配 " + std::to_string(matches) + "+ 处，需增加固定字节或人工收窄";
      rep.candidates.push_back(c);
      if (matches == 1) break;  // 已得到唯一匹配，不必再试更长
    }
    if (rep.candidates.size() >= 40) break;
  }
  std::stable_sort(rep.candidates.begin(), rep.candidates.end(), [](const HookCandidate& a, const HookCandidate& b) {
    bool au = a.unique_matches == 1, bu = b.unique_matches == 1;
    if (au != bu) return au;
    return a.fixed_bytes > b.fixed_bytes;
  });
  if (rep.candidates.size() > 20) rep.candidates.resize(20);
  if (xrefs.empty())
    rep.note = "未找到指向这些锚点的 RIP 相对引用。可用 --anchors 传入你自己的字符串（例如某个模型路径），"
               "或直接用 wowmod adapt 从邻近版本的特征推导";
  return rep;
}

Json HookCandidate::to_json() const {
  Json j = Json::make_object();
  j.set("anchor", Json::make_string(anchor));
  j.set("stringRva", Json::make_number(static_cast<double>(string_rva)));
  j.set("codeRva", Json::make_number(static_cast<double>(code_rva)));
  j.set("fileOffset", Json::make_number(static_cast<double>(file_offset)));
  j.set("pattern", Json::make_string(pattern));
  j.set("fixedBytes", Json::make_number(static_cast<double>(fixed_bytes)));
  j.set("uniqueMatches", Json::make_number(static_cast<double>(unique_matches)));
  j.set("executable", Json::make_bool(executable));
  j.set("reason", Json::make_string(reason));
  return j;
}

Json DiscoveryReport::to_json() const {
  Json j = Json::make_object();
  j.set("exe", Json::make_string(exe));
  j.set("pe", Json::make_bool(pe));
  j.set("arch", Json::make_string(arch));
  Json a = Json::make_array(); for (const auto& s : anchors) a.push(Json::make_string(s));
  j.set("anchors", a);
  Json f = Json::make_array(); for (const auto& s : anchors_found) f.push(Json::make_string(s));
  j.set("anchorsFound", f);
  Json c = Json::make_array(); for (const auto& x : candidates) c.push(x.to_json());
  j.set("candidates", c);
  j.set("note", Json::make_string(note));
  return j;
}

}  // namespace wowmod
