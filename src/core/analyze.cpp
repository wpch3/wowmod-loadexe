// 映像 → loose-file hook 方案的推导实现。
// SPDX-License-Identifier: MIT
#include "wowmod/analyze.hpp"

#include <chrono>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>

#include "wowmod/launcher_stub.hpp"
#include "wowmod/util.hpp"
#include "wowmod/xref.hpp"

namespace wowmod {

const std::vector<LooseFileMarker>& loose_file_markers() {
  // 说明：
  //  * "Locally overridden files" 是客户端崩溃日志里那段列表的标题（见本仓库
  //    2026-11-13_18.56.22_Crash_2416.txt 第 409 行附近），说明客户端内部维护着
  //    「本地覆盖文件 id -> 路径」表，这正是 loose 文件替换的落点。
  //  * 其余条目是 CASC/存储层常见标识，用于在剥离字符串的客户端上做交叉验证。
  static const std::vector<LooseFileMarker> kMarkers = {
      {"Locally overridden files", "客户端自己打印的本地覆盖文件清单标题", 100},
      {"locally overridden", "同上（小写变体）", 90},
      {"overridden files", "同上（无前缀变体）", 80},
      {".flavor.info", "客户端读取的本地覆盖标记文件", 60},
      {"CASC", "存储层模块名", 30},
      {"FileDataID", "按 id 取文件的日志/断言文本", 70},
      {"data/tree", "本地数据目录（data/tree 是 loose 文件根）", 50},
  };
  return kMarkers;
}

Json AnalyzeResult::to_json() const {
  Json out = Json::make_object();
  out.set("analyzer", Json::make_string("wowmod-loose-file-analyzer"));
  out.set("ok", Json::make_bool(ok));
  out.set("imageSize", Json::make_number(static_cast<double>(image_size)));
  out.set("baseVa", Json::make_string(to_hex(base_va, 16)));
  if (!error.empty()) out.set("error", Json::make_string(error));

  // 找到但无代码引用的字符串，单独一组（以前被静默丢弃）
  Json orphans = Json::make_array();
  for (const auto& o : orphan_strings) {
    Json j = Json::make_object();
    j.set("marker", Json::make_string(o.marker));
    j.set("rva", Json::make_string(to_hex(o.rva, 16)));
    j.set("utf16", Json::make_bool(o.utf16));
    orphans.push(j);
  }
  out.set("orphanStrings", orphans);
  out.set("usedFileRemap", Json::make_bool(used_file_remap));

  Json sh = Json::make_array();
  for (const auto& h : string_hits) {
    Json o = Json::make_object();
    o.set("marker", Json::make_string(h.marker));
    o.set("rva", Json::make_string(to_hex(h.rva, 1)));
    o.set("utf16", Json::make_bool(h.utf16));
    o.set("refCount", Json::make_number(static_cast<double>(h.refs.size())));
    Json refs = Json::make_array();
    for (const auto& r : h.refs) {
      Json ro = Json::make_object();
      ro.set("at", Json::make_string(to_hex(r.at, 1)));
      ro.set("form", Json::make_string(r.form));
      refs.push(ro);
    }
    o.set("refs", refs);
    Json fns = Json::make_array();
    for (size_t f : h.functions) fns.push(Json::make_string(to_hex(f, 1)));
    o.set("functions", fns);
    sh.push(o);
  }
  out.set("stringHits", sh);

  Json sites_json = Json::make_array();
  for (const auto& s : sites) {
    Json o = Json::make_object();
    o.set("marker", Json::make_string(s.marker));
    o.set("functionRva", Json::make_string(to_hex(s.function_rva, 1)));
    o.set("refRva", Json::make_string(to_hex(s.ref_rva, 1)));
    o.set("hookable", Json::make_bool(s.site.ok));
    o.set("copyLen", Json::make_number(static_cast<double>(s.site.copy_len)));
    o.set("relocatable", Json::make_bool(s.site.relocatable));
    o.set("hasRipRelative", Json::make_bool(s.site.has_rip_relative));
    o.set("hasJump", Json::make_bool(s.site.has_jump));
    o.set("reason", Json::make_string(s.site.reason));
    Json pr = Json::make_array();
    for (const auto& w : s.function_prologue) {
      Json wo = Json::make_object();
      wo.set("rva", Json::make_string(to_hex(w.rva, 1)));
      wo.set("bytes", Json::make_string(w.text));
      pr.push(wo);
    }
    o.set("prologue", pr);
    sites_json.push(o);
  }
  out.set("sites", sites_json);

  Json ids = Json::make_array();
  for (const auto& c : id_candidates) {
    Json o = Json::make_object();
    o.set("functionRva", Json::make_string(to_hex(c.rva, 1)));
    o.set("cmpRva", Json::make_string(to_hex(c.cmp_rva, 1)));
    o.set("score", Json::make_number(c.score));
    o.set("scale", Json::make_number(c.scale));
    o.set("evidence", Json::make_string(c.evidence));
    ids.push(o);
  }
  out.set("idLookupCandidates", ids);

  Json dt = Json::make_array();
  for (const auto& t : detour_targets) {
    Json o = Json::make_object();
    o.set("marker", Json::make_string(t.marker));
    o.set("functionRva", Json::make_string(to_hex(t.function_rva, 1)));
    o.set("hookable", Json::make_bool(t.hookable));
    o.set("copyLen", Json::make_number(static_cast<double>(t.copy_len)));
    o.set("reason", Json::make_string(t.reason));
    dt.push(o);
  }
  out.set("detourTargets", dt);

  out.set("warning",
          Json::make_string("这是结构推断，不是 ABI 证明。未经运行期观察确认的 id 寄存器/返回值语义"
                            "不得直接用于打补丁。"));
  return out;
}

std::string AnalyzeResult::to_text() const {
  std::string s;
  char buf[512];
  std::snprintf(buf, sizeof(buf), "映像大小 %.2f MB, 基址 0x%s\n", image_size / 1048576.0,
                to_hex(base_va, 16).c_str());
  s += buf;
  if (!ok) {
    s += "分析失败: " + error + "\n";
    return s;
  }

  s += "\n== 0) 数据布局 ==\n";
  if (used_file_remap) {
    // 这是实测结论，不是猜的：原样扫描零引用，重映射后就有引用。
    s += "  原始数据是【磁盘文件布局】（节的 PointerToRawData != VirtualAddress）。\n"
         "  已按节表重映射成内存布局后再分析，下面的 RVA 都是重映射后的 RVA。\n"
         "  证据：原样扫描 0 个代码引用，重映射后找到了引用。\n";
  } else {
    s += "  原始数据是【内存布局】（RVA 可直接当偏移用），无需重映射。\n";
  }

  s += "\n== 1) 已知字符串与交叉引用 ==\n";
  if (string_hits.empty() && orphan_strings.empty()) {
    s += "  没有找到任何已知标记字符串。\n"
         "  → 说明这份映像还不是解密后的客户端主模块，或者字符串被剥掉了。\n"
         "    请对 Wow_loader.dll / 主 exe 的【内存映像】再跑一次。\n";
  }
  // 找到了字符串、但没有任何代码引用 —— 必须如实报出来。
  if (!orphan_strings.empty()) {
    std::snprintf(buf, sizeof(buf),
                  "  找到 %zu 处标记字符串，但没有任何 RIP 相对代码引用：\n",
                  orphan_strings.size());
    s += buf;
    size_t shown = 0;
    for (const auto& o : orphan_strings) {
      if (shown++ >= 12) { s += "      ...\n"; break; }
      std::snprintf(buf, sizeof(buf), "      [%s] rva=0x%s%s\n", o.marker.c_str(),
                    to_hex(o.rva, 1).c_str(), o.utf16 ? " (UTF-16)" : "");
      s += buf;
    }
    s += "  → 字符串确实在映像里，只是没有被 lea/mov 直接引用。\n";
    if (!used_file_remap)
      s += "    可能是经字符串表/哈希间接取址，或引用用的是 32 位绝对地址。\n";
  }
  for (const auto& h : string_hits) {
    std::snprintf(buf, sizeof(buf), "  [%s] rva=0x%s 引用 %zu 处\n", h.marker.c_str(),
                  to_hex(h.rva, 1).c_str(), h.refs.size());
    s += buf;
    size_t shown = 0;
    for (const auto& r : h.refs) {
      if (shown++ >= 6) { s += "      ...\n"; break; }
      std::snprintf(buf, sizeof(buf), "      0x%s  %s -> 目标\n", to_hex(r.at, 1).c_str(),
                    r.form.c_str());
      s += buf;
    }
    for (size_t f : h.functions) {
      std::snprintf(buf, sizeof(buf), "      函数起点 0x%s\n", to_hex(f, 1).c_str());
      s += buf;
    }
  }

  s += "\n== 2) hook 点方案（按函数起点） ==\n";
  if (sites.empty()) s += "  无。\n";
  for (const auto& st : sites) {
    std::snprintf(buf, sizeof(buf), "  fn=0x%s (标记: %s) 可 hook=%s 覆盖 %zu 字节 — %s\n",
                  to_hex(st.function_rva, 1).c_str(), st.marker.c_str(),
                  st.site.ok ? "是" : "否", st.site.copy_len, st.site.reason.c_str());
    s += buf;
    for (const auto& w : st.function_prologue) {
      std::snprintf(buf, sizeof(buf), "      +0x%s  %s\n", to_hex(w.rva, 1).c_str(),
                    w.text.c_str());
      s += buf;
    }
  }

  s += "\n== 2b) 目标函数语义风险（重要） ==\n";
  s += "  下面这些函数只是【引用了那个字符串】。字符串出现在哪里，决定了这个\n"
       "  函数是什么性质 —— 一旦 hook 错，轻则无效、重则崩溃：\n"
       "\n"
       "  「Locally overridden files」在 12.0.7 里出现在【崩溃日志】里\n"
       "  （crash dump 会打印 'Locally overridden files' 再逐行列出覆盖的文件）。\n"
       "  也就是说引用它的函数多半是【崩溃/诊断报告格式化函数】，不是资源加载路径。\n"
       "\n"
       "  实测佐证：曾经 hook 过这个函数（rva=0x33e1890），结果\n"
       "    - 整个游戏流程里它被调用 0 次（正常路径根本不走）\n"
       "    - 客户端随后报 EXCEPTION_INTERNAL_ERROR / 0xC00000E5\n"
       "  因为崩溃处理器自己被打坏了，连崩溃日志都写不出来。\n"
       "\n"
       "  结论：这类目标【不要用来做功能 hook】。它只适合在确认安全后用来\n"
       "  观察 ABI（仍需 --apply 显式开启）。\n";

  s += "\n== 3) 推荐 detour 目标（每个引用标记字符串的函数一条） ==\n";
  if (detour_targets.empty()) s += "  无。\n";
  for (const auto& t : detour_targets) {
    std::snprintf(buf, sizeof(buf), "  fn=0x%s [%s] %s 覆盖 %zu 字节 — %s\n",
                  to_hex(t.function_rva, 1).c_str(), t.marker.c_str(),
                  t.hookable ? "可 hook" : "不可 hook", t.copy_len, t.reason.c_str());
    s += buf;
  }

  s += "\n== 4) FileDataID 查找函数候选 ==\n";
  s += render_candidates(id_candidates);
  return s;
}

// 把磁盘文件布局重映射成内存布局（节数据从 PointerToRawData 搬到 VirtualAddress）。
bool remap_file_to_image(const ImageView& in, std::vector<uint8_t>* out) {
  if (!out || !in.valid() || in.size < 0x200) return false;
  if (in.data[0] != 'M' || in.data[1] != 'Z') return false;
  uint32_t lfanew = 0;
  std::memcpy(&lfanew, in.data + 0x3C, 4);
  if (static_cast<size_t>(lfanew) + 0x40 > in.size) return false;
  if (std::memcmp(in.data + lfanew, "PE\0\0", 4) != 0) return false;
  const uint8_t* fh = in.data + lfanew + 4;
  uint16_t nsect = 0, opt_size = 0;
  std::memcpy(&nsect, fh + 2, 2);
  std::memcpy(&opt_size, fh + 16, 2);
  const uint8_t* oh = fh + 20;
  if (static_cast<uint16_t>(oh[0] | (oh[1] << 8)) != 0x20B) return false;
  uint32_t size_of_image = 0;
  std::memcpy(&size_of_image, oh + 56, 4);
  if (size_of_image == 0 || size_of_image > (512u << 20)) return false;
  const uint8_t* sh = oh + opt_size;
  const size_t sh_end = static_cast<size_t>(sh - in.data) + static_cast<size_t>(nsect) * 40;
  if (sh_end > in.size) return false;

  out->assign(size_of_image, 0);
  // 头区原样搬（含节表）
  const size_t hdr = (std::min)({static_cast<size_t>(0x400), in.size,
                                 static_cast<size_t>(size_of_image)});
  std::memcpy(out->data(), in.data, hdr);
  bool any = false;
  for (uint16_t i = 0; i < nsect; ++i) {
    const uint8_t* e = sh + static_cast<size_t>(i) * 40;
    uint32_t vsize = 0, va = 0, raw_size = 0, raw_ptr = 0;
    std::memcpy(&vsize, e + 8, 4);
    std::memcpy(&va, e + 12, 4);
    std::memcpy(&raw_size, e + 16, 4);
    std::memcpy(&raw_ptr, e + 20, 4);
    const size_t avail_raw = in.size > raw_ptr ? in.size - raw_ptr : 0;
    const size_t avail_va = size_of_image > va ? size_of_image - va : 0;
    const size_t want = vsize ? vsize : raw_size;
    const size_t n = (std::min)((std::min)(static_cast<size_t>(raw_size), want),
                                (std::min)(avail_raw, avail_va));
    if (n == 0) continue;
    std::memcpy(out->data() + va, in.data + raw_ptr, n);
    any = true;
  }
  return any;
}

AnalyzeResult analyze_image(const ImageView& img, const AnalyzeOptions& opt) {
  AnalyzeResult res;
  res.image_size = img.size;
  res.base_va = img.base_va;
  if (!img.valid()) {
    res.error = "映像为空";
    return res;
  }

  // ---- 1) 字符串与交叉引用 ----
  // 性能关键：分析阶段的历史实现是「每个 (标记, 命中) 各扫一遍全映像」，
  // 108MB 客户端映像上有十几个标记、每个多次命中 —— 那等于上百次全盘
  // 遍历，必然卡死。现在改成两遍：
  //   1. 找字符串命中，收集全部目标 VA（这步只有几次 SIMD 字符串搜索）
  //   2. 用 find_code_refs_to_many 一次全盘扫描解析所有目标
  std::set<size_t> seen_functions;
  const auto t_stage1 = std::chrono::steady_clock::now();
  auto elapsed1 = [&]() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_stage1).count();
  };
  auto budget1_left = [&]() {
    if (opt.refs_budget_seconds <= 0.0) return true;
    return elapsed1() < opt.refs_budget_seconds;
  };

  struct RawHit {
    std::string marker;
    size_t rva;
    bool utf16;
  };
  std::vector<RawHit> raw;
  size_t marker_index = 0;
  const size_t marker_total = loose_file_markers().size();
  for (const auto& marker : loose_file_markers()) {
    if (!budget1_left()) break;
    if (opt.progress) opt.progress("strings", marker_index, marker_total);
    ++marker_index;
  }
  if (opt.progress) opt.progress("strings", marker_total, marker_total);

  // 一次全盘扫描解析所有目标的 RIP 相对引用。
  //
  // img_for_refs 默认是原始视图。如果扫完一个引用都没有，就按节表把
  // 「磁盘文件布局」重映射成「内存布局」，然后在【新视图上重新找字符串、
  // 重新解析引用】—— 必须重找字符串，因为重映射会改变字符串的偏移，
  // 复用旧偏移会得到假阳性结果。
  //
  // 这不是猜：两个视图各自跑完整流程，哪个真能找到代码引用就用哪个。
  // 真实客户端那块 108MB（MZ 头、SizeOfImage 全对，字符串在、xref 全空）
  // 正好是这个情形。
  ImageView img_for_refs = img;
  bool used_remap = false;
  if (opt.progress) opt.progress("xref", 0, 1);
  const double refs_budget =
      opt.refs_budget_seconds > 0 ? (std::max)(1.0, opt.refs_budget_seconds - elapsed1()) : 0.0;

  // 内部：在给定视图上「找字符串 + 解析引用」，返回是否找到了任何引用。
  std::vector<uint8_t> remapped;
  // 注意：即使最终一个引用都没有，out_raw 也必须保留（报告要写明
  // "字符串找到了但没有引用"）。返回值只表示"有没有引用"。
  auto run_on_view = [&](const ImageView& view, std::vector<RawHit>* out_raw,
                         std::map<uint64_t, std::vector<CodeRef>>* out_refs) -> bool {
    out_raw->clear();
    out_refs->clear();
    if (!view.valid()) return false;
    // 每个标记最多收 kMaxHitsPerMarker 处命中。
    //
    // 这里踩过一个真实的坑：原来写死 8，而真实的 12.0.7 客户端里
    // "FileDataID" 出现 10+ 次，第 9 处之后【恰好】含有唯一的 lea 引用。
    // 上限一卡，引用就被挤掉，报告变成"字符串找到了但一个引用都没有"
    // —— 看起来像分析算法坏了，其实是采样截断。现在放宽到 64。
    constexpr size_t kMaxHitsPerMarker = 64;
    std::vector<uint64_t> tg;
    size_t mi = 0;
    const size_t mt = loose_file_markers().size();
    for (const auto& marker : loose_file_markers()) {
      if (opt.progress) opt.progress("strings", mi++, mt);
      auto hit = find_bytes(view, marker.text, false, kMaxHitsPerMarker, 5.0);
      bool u16 = false;
      if (hit.empty()) {
        hit = find_bytes(view, marker.text, true, kMaxHitsPerMarker, 5.0);
        u16 = true;
      }
      for (size_t h : hit) {
        out_raw->push_back(RawHit{marker.text, h, u16});
        tg.push_back(view.va_of(h));
      }
    }
    if (tg.empty()) return false;
    *out_refs = find_code_refs_to_many(view, tg, 64, refs_budget);
    return !out_refs->empty();  // 引用为空也保留 out_raw
  };

  std::vector<RawHit> raw2;
  std::map<uint64_t, std::vector<CodeRef>> ref_map;
  bool got_refs = run_on_view(img, &raw2, &ref_map);
  // 先把"字符串找到了"这件事记下来；没有引用时报告必须说明，
  // 而不是像以前那样写成"没有找到任何已知标记字符串"。
  raw = raw2;
  if (!got_refs && opt.allow_file_remap && remap_file_to_image(img, &remapped)) {
    // 原始视图没有引用 -> 试试文件布局重映射
    if (opt.progress) opt.progress("xref(重映射)", 0, 1);
    ImageView iv2;
    iv2.data = remapped.data();
    iv2.size = remapped.size();
    iv2.base_va = img.base_va;
    std::vector<RawHit> raw3;
    std::map<uint64_t, std::vector<CodeRef>> refs3;
    if (run_on_view(iv2, &raw3, &refs3)) {
      raw = std::move(raw3);
      ref_map = std::move(refs3);
      img_for_refs = iv2;
      used_remap = true;
    }
    if (opt.progress) opt.progress("xref(重映射)", 1, 1);
  }
  res.used_file_remap = used_remap;
  if (opt.progress) opt.progress("xref", 1, 1);

  for (const auto& rh : raw) {
    StringHit sh;
    sh.marker = rh.marker;
    sh.rva = rh.rva;
    sh.utf16 = rh.utf16;
    auto it = ref_map.find(img_for_refs.va_of(rh.rva));
    if (it != ref_map.end()) sh.refs = it->second;
    for (const auto& r : sh.refs) {
      const size_t fn = find_function_start(img_for_refs, r.at, 0x3000);
      if (fn != SIZE_MAX && fn != r.at) {
        if (std::find(sh.functions.begin(), sh.functions.end(), fn) == sh.functions.end())
          sh.functions.push_back(fn);
      }
    }
    if (sh.refs.empty()) {
      // 保留下来：报告里要写明"字符串找到了，但没有任何 RIP 相对引用"。
      // 以前这里直接 continue，于是报告写着「没有找到任何标记字符串」，
      // 而上面明明写着「命中标记: 5 个」—— 自相矛盾，把排查完全带偏。
      res.orphan_strings.push_back(
          AnalyzeResult::OrphanString{rh.marker, rh.rva, rh.utf16});
      continue;
    }
    res.string_hits.push_back(std::move(sh));
  }

  // ---- 2) hook 点方案 ----
  const size_t max_fn = opt.max_functions ? opt.max_functions : 16;
  for (const auto& h : res.string_hits) {
    for (size_t fn : h.functions) {
      if (seen_functions.size() >= max_fn) break;
      if (seen_functions.count(fn)) continue;
      seen_functions.insert(fn);
      AnalyzeResult::Site site;
      site.marker = h.marker;
      site.function_rva = fn;
      site.ref_rva = h.refs.empty() ? 0 : h.refs.front().at;
      site.site = plan_hook_site(img_for_refs, fn, 14);
      site.function_prologue = disassemble_window(img_for_refs, fn, site.site.copy_len + 12);
      res.sites.push_back(std::move(site));
    }
  }

  // ---- 3) FileDataID 查找候选 ----
  if (opt.scan_id_lookup) {
    if (opt.progress) opt.progress("id-scan", 0, 1);
    res.id_candidates = scan_id_lookup_candidates(img_for_refs, 16, opt.id_budget_seconds);
    if (opt.progress) opt.progress("id-scan", 1, 1);
  }

  // ---- 3b) 推荐 detour 目标 ----
  {
    std::set<size_t> seen;
    for (const auto& site : res.sites) {
      if (!site.site.ok || seen.count(site.function_rva)) continue;
      seen.insert(site.function_rva);
      AnalyzeResult::DetourTarget t;
      t.marker = site.marker;
      t.function_rva = site.function_rva;
      t.hookable = true;
      t.copy_len = site.site.copy_len;
      t.reason = site.site.reason;
      res.detour_targets.push_back(std::move(t));
    }
    // 不可 hook 的也列出来，方便诊断
    for (const auto& site : res.sites) {
      if (site.site.ok || seen.count(site.function_rva)) continue;
      seen.insert(site.function_rva);
      AnalyzeResult::DetourTarget t;
      t.marker = site.marker;
      t.function_rva = site.function_rva;
      t.hookable = false;
      t.reason = site.site.reason;
      res.detour_targets.push_back(std::move(t));
    }
  }

  res.ok = true;
  return res;
}

AnalyzeResult analyze_image_file(const std::string& path, uint64_t base_va,
                                 const AnalyzeOptions& opt) {
  AnalyzeResult res;
  std::vector<uint8_t> bytes;
  std::string err;
  if (!read_binary_file(path, &bytes, &err)) {
    res.error = "读取映像失败: " + err;
    return res;
  }
  ImageView img;
  img.data = bytes.data();
  img.size = bytes.size();
  img.base_va = base_va;
  AnalyzeOptions o = opt;
  AnalyzeResult r = analyze_image(img, o);
  // analyze_image 内部的 ImageView 只在本次调用中有效，但结果里不含指针，安全。
  return r;
}

bool map_pe_image(const std::vector<uint8_t>& file, std::vector<uint8_t>* out, uint64_t* base_va,
                  std::string* err) {
  const PeLayout pe = parse_pe_file(file);
  if (!pe.ok) {
    if (err) *err = "不是可解析的 x64 PE: " + pe.error;
    return false;
  }
  if (pe.size_of_image == 0 || pe.size_of_image > 1024u * 1024u * 1024u) {
    if (err) *err = "SizeOfImage 异常";
    return false;
  }
  out->assign(pe.size_of_image, 0);
  // 头区（含节表）原样复制
  const size_t hdr = std::min<size_t>(file.size(), pe.sections.empty() ? 0x400 : pe.sections[0].raw_ptr);
  std::memcpy(out->data(), file.data(), std::min(hdr, static_cast<size_t>(pe.size_of_image)));
  for (const auto& s : pe.sections) {
    if (s.raw_size == 0 || s.va >= pe.size_of_image) continue;
    const size_t n = std::min<size_t>({static_cast<size_t>(s.raw_size),
                                       file.size() > s.raw_ptr ? file.size() - s.raw_ptr : 0,
                                       pe.size_of_image - s.va});
    if (n) std::memcpy(out->data() + s.va, file.data() + s.raw_ptr, n);
  }
  if (base_va) *base_va = pe.image_base;
  return true;
}

bool load_analysis_image(const std::string& path, bool already_mapped, std::vector<uint8_t>* out,
                         uint64_t* base_va, std::string* err) {
  std::vector<uint8_t> file;
  if (!read_binary_file(path, &file, err)) return false;
  if (already_mapped) {
    *out = std::move(file);
    if (base_va) *base_va = 0;
    return true;
  }
  uint64_t base = 0;
  if (map_pe_image(file, out, &base, nullptr)) {
    if (base_va) *base_va = base;
    return true;
  }
  // 不是 PE：当作已经是映像布局（例如手工切出来的 .text）
  *out = std::move(file);
  if (base_va) *base_va = 0;
  return true;
}

}  // namespace wowmod
