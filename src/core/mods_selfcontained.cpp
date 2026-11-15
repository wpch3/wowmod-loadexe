// 自包含模组扫描：见 mods_selfcontained.hpp。
// SPDX-License-Identifier: MIT
#include "wowmod/mods_selfcontained.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "wowmod/util.hpp"
#include "wowmod/mod_entry.hpp"

namespace wowmod {
namespace win {
namespace {

// 游戏里按 FileDataID 存取的资源前缀。与 tools/build-mod-mappings.py 保持一致，
// 目的只是"不要把我自己仓库里的同名目录当模组"。
const char* kPrefixes[] = {"character/", "creature/", "item/",      "interface/",
                           "sound/",     "fonts/",    "world/",     "spells/",
                           "particles/", "environments/", "dungeons/", "tileset/",
                           "cameras/",   "anim/"};

std::string norm_key(const std::string& in) {
  std::string s = in;
  std::replace(s.begin(), s.end(), '\\', '/');
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    if (c == ' ' || c == '\t' || c == '"') continue;   // listfile 里有带空格的名字
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  while (out.rfind("./", 0) == 0) out = out.substr(2);
  while (!out.empty() && out.front() == '/') out.erase(out.begin());
  return out;
}

std::string base_name(const std::string& p) {
  const size_t s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}

size_t tail_score(const std::string& a, const std::string& b) {
  std::vector<std::string> x, y;
  {
    std::string cur;
    for (char c : a) { if (c == '/') { x.push_back(cur); cur.clear(); } else cur.push_back(c); }
    x.push_back(cur);
  }
  {
    std::string cur;
    for (char c : b) { if (c == '/') { y.push_back(cur); cur.clear(); } else cur.push_back(c); }
    y.push_back(cur);
  }
  size_t n = 0;
  for (size_t i = 1; i <= std::min(x.size(), y.size()); ++i) {
    if (x[x.size() - i] != y[y.size() - i]) break;
    ++n;
  }
  return n;
}

// 把「磁盘上的相对路径」裁剪成「游戏内相对路径」。
//
// 模组的真实形态五花八门，实测过的四种：
//   Character\BloodElf\...                          -> 已经在游戏根
//   T21WarriorNSFW\item\texturecomponents\...       -> 多一层包名
//   Titaa Hawkstrider Mount\Creature\cockatrice\... -> 多一层包名
//   Wrath NPC Pack\Textures\BakedNpcTextures\...    -> 根本没有游戏前缀
//
// 所以不能用一个"全局基准目录"去算（那样只能符合同一种形态）。
// 正确做法是【逐文件】在路径里找第一个已知游戏前缀目录，从那里截断。
// 找不到前缀时返回空串，交给"文件名 + 尾部目录"那条模糊路径处理。
std::string strip_to_game_prefix(const std::string& rel) {
  const std::string low = norm_key(rel);
  // 切段，逐段比对
  std::vector<std::string> segs;
  std::string cur;
  for (char c : low) {
    if (c == '/') { segs.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  segs.push_back(cur);

  for (size_t i = 0; i + 1 < segs.size(); ++i) {
    for (const char* pfx : kPrefixes) {
      // kPrefixes 带结尾 '/'，段名比对时去掉
      std::string name(pfx);
      if (!name.empty() && name.back() == '/') name.pop_back();
      if (segs[i] == name) {
        std::string out;
        for (size_t k = i; k < segs.size(); ++k) {
          if (k != i) out.push_back('/');
          out += segs[k];
        }
        return out;
      }
    }
  }
  return "";
}

struct ListfileTable {
  std::unordered_map<std::string, uint64_t> by_key;    // 归一化路径 -> id
  std::unordered_map<std::string, std::string> path_of; // 归一化路径 -> 官方写法
  std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::string>>> by_base;
  size_t loaded = 0;
};

}  // namespace

std::vector<std::string> split_listfiles(const std::string& spec) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : spec) {
    if (c == ';') {
      if (!cur.empty()) out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

SelfContainedReport build_selfcontained_mods(const std::string& mods_dir,
                                            const std::vector<std::string>& listfiles) {
  SelfContainedReport rep;

  // ---- 1. 读 listfile ----
  ListfileTable lf;
  for (const auto& path : listfiles) {
    std::string text;
    std::string err;
    if (!read_text_file(path, &text, &err)) {
      rep.error += (rep.error.empty() ? "" : "; ") + std::string("读不到 listfile: ") + path +
                   (err.empty() ? "" : (" (" + err + ")"));
      continue;
    }
    size_t pos = 0;
    while (pos < text.size()) {
      size_t nl = text.find('\n', pos);
      const std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos
                                                                        : nl - pos);
      pos = (nl == std::string::npos) ? text.size() : nl + 1;
      const std::string t = trim(line);
      if (t.empty() || t[0] == '#') continue;
      const size_t semi = t.find(';');
      if (semi == std::string::npos) continue;
      const std::string id_s = trim(t.substr(0, semi));
      if (id_s.empty()) continue;
      bool digits = true;
      for (char c : id_s) if (!std::isdigit(static_cast<unsigned char>(c))) digits = false;
      if (!digits) continue;
      const uint64_t id = std::strtoull(id_s.c_str(), nullptr, 10);
      const std::string raw = trim(t.substr(semi + 1));
      if (raw.empty()) continue;
      const std::string key = norm_key(raw);
      if (key.empty() || lf.by_key.count(key)) continue;
      lf.by_key[key] = id;
      lf.path_of[key] = raw;
      lf.by_base[base_name(key)].push_back({id, raw});
    }
  }
  if (lf.by_key.empty()) {
    if (rep.error.empty()) rep.error = "listfile 里没有解析出任何 id;路径 行";
    return rep;
  }

  // ---- 2. 扫模组目录 ----
  //
  // 注意：list_files_recursive 返回的是【相对 root 的路径】，不是绝对路径。
  // 之前当成绝对路径用，于是 rel_of() 一个都算不出来 —— 表现就是
  // "扫到 N 个文件，解析出 0 项"。这里自己拼绝对路径。
  std::string err;
  const auto rels = list_files_recursive(mods_dir, &err);
  if (rels.empty()) {
    rep.error = err.empty() ? ("模组目录里没有文件: " + mods_dir) : err;
    return rep;
  }
  std::string abs_root = absolute_path(mods_dir);
  std::replace(abs_root.begin(), abs_root.end(), '\\', '/');
  while (!abs_root.empty() && abs_root.back() == '/') abs_root.pop_back();

  std::vector<std::string> files;
  files.reserve(rels.size());
  for (const auto& r : rels) {
    std::string x = r;
    std::replace(x.begin(), x.end(), '\\', '/');
    while (!x.empty() && x.front() == '/') x.erase(x.begin());
    files.push_back(abs_root + "/" + x);
  }
  rep.files_scanned = files.size();

  // game_root 只用于报告（"这份模组是相对哪个目录组织的"）。
  // 游戏内路径不再依赖它 —— 见 strip_to_game_prefix。
  rep.game_root = abs_root;

  std::unordered_set<uint64_t> seen;
  const std::string root_prefix = abs_root + "/";
  for (const auto& abs : files) {
    // 相对模组目录的路径
    std::string disk_rel = abs;
    if (disk_rel.size() > root_prefix.size() &&
        disk_rel.compare(0, root_prefix.size(), root_prefix) == 0)
      disk_rel = disk_rel.substr(root_prefix.size());
    if (disk_rel.empty()) continue;
    // 裁剪成游戏内路径；裁不出来就保留整条（后面按文件名模糊匹配）
    std::string rel = strip_to_game_prefix(disk_rel);
    if (rel.empty()) rel = disk_rel;
    // 说明文件 / listfile 本身不是游戏资源，别报成"解析不出来"
    {
      const std::string low = norm_key(rel);
      const std::string ext = file_extension(low);
      const std::string base_n = base_name(low);
      if (base_n == "lf.csv" || base_n == "listfile.csv" || ext == ".csv" || ext == ".md" ||
          ext == ".txt" || ext == ".json" || base_n.rfind("readme", 0) == 0 ||
          base_n.rfind("license", 0) == 0)
        continue;
    }
    const std::string key = norm_key(rel);

    // 精确匹配
    uint64_t id = 0;
    std::string official;
    const char* how = nullptr;
    auto it = lf.by_key.find(key);
    if (it != lf.by_key.end()) {
      id = it->second;
      official = lf.path_of[key];
      how = "exact";
      ++rep.by_exact;
    } else {
      // _HD 变体
      if (key.size() > 4 && key.compare(key.size() - 4, 4, ".blp") == 0) {
        const std::string stem = key.substr(0, key.size() - 4);
        std::string cand;
        if (stem.size() > 3 && stem.compare(stem.size() - 3, 3, "_hd") == 0)
          cand = stem.substr(0, stem.size() - 3) + ".blp";
        else
          cand = stem + "_hd.blp";
        auto it2 = lf.by_key.find(cand);
        if (it2 != lf.by_key.end()) {
          id = it2->second;
          official = lf.path_of[cand];
          how = "hd";
          ++rep.by_hd;
        }
      }
      // 文件名 + 尾部目录打分
      if (!id) {
        const std::string base_name_ = base_name(key);
        auto it3 = lf.by_base.find(base_name_);
        if (it3 != lf.by_base.end()) {
          if (it3->second.size() == 1) {
            id = it3->second[0].first;
            official = it3->second[0].second;
            how = "name";
            ++rep.by_name;
          } else {
            size_t best = 0;
            std::pair<uint64_t, std::string> winner{0, ""};
            int ties = 0;
            for (const auto& c : it3->second) {
              const size_t sc = tail_score(key, norm_key(c.second));
              if (sc > best) { best = sc; winner = c; ties = 1; }
              else if (sc == best) ++ties;
            }
            if (best >= 2 && ties == 1) {
              id = winner.first;
              official = winner.second;
              how = "name+tail";
              ++rep.by_name;
            } else {
              // 重名被拒绝：同时计入 ambiguous 与 missing，因为对用户来说
              // 结果都是"这个文件不会生效"，而原因需要单独说清楚。
              ++rep.ambiguous;
              ++rep.missing;
              if (rep.unresolved.size() < 40) rep.unresolved.push_back(rel + "  (重名，无法确定)");
              continue;
            }
          }
        }
      }
    }

    if (!id) {
      ++rep.missing;
      if (rep.unresolved.size() < 40) rep.unresolved.push_back(rel);
      continue;
    }
    if (seen.count(id)) {
      ++rep.duplicates;   // Arctium: "Skipping overlapping file 'id - f'."
      continue;
    }
    seen.insert(id);

    ModEntry e;
    e.file_data_id = id;
    e.game_path = normalize_game_path(rel);
    e.local_path = abs;
    e.file_exists = true;
    rep.entries.push_back(std::move(e));
    ++rep.matched;
    (void)how;
    (void)official;
  }

  rep.ok = !rep.entries.empty();
  if (!rep.ok && rep.error.empty()) rep.error = "一个 FileDataID 都没解析出来";
  return rep;
}

}  // namespace win
}  // namespace wowmod
