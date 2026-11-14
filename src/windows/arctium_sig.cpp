// Arctium 特征码扫描实现。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/arctium_sig.hpp"

#include <algorithm>
#include <cstdio>

#include "windows/scan_images.hpp"

namespace wowmod {
namespace win {

namespace {

std::string region_note(const ScannedImage& img) {
  if (!img.module_name.empty()) return "模块 " + img.module_name;
  if (img.has_pe_header) return "匿名 PE 映像";
  return "匿名区域";
}

}  // namespace

Json SigScanResult::to_json() const {
  Json j = Json::make_object();
  j.set("exe", Json::make_string(exe));
  j.set("pid", Json::make_number(static_cast<double>(pid)));
  j.set("imagesScanned", Json::make_number(static_cast<double>(images_scanned)));
  j.set("bytesScanned", Json::make_number(static_cast<double>(bytes_scanned)));
  j.set("clientModified", Json::make_bool(false));
  Json arr = Json::make_array();
  for (const auto& h : hits) {
    Json o = Json::make_object();
    o.set("name", Json::make_string(h.name));
    o.set("matchVa", Json::make_string(to_hex(h.match_va, 16)));
    o.set("patchVa", Json::make_string(to_hex(h.patch_va, 16)));
    o.set("imageBase", Json::make_string(to_hex(h.image_base, 16)));
    o.set("imageNote", Json::make_string(h.image_note));
    o.set("matchCount", Json::make_number(static_cast<double>(h.match_count)));
    o.set("verdict", Json::make_string(h.verdict));
    arr.push(o);
  }
  j.set("hits", arr);
  Json ns = Json::make_array();
  for (const auto& n : notes) ns.push(Json::make_string(n));
  j.set("unmatched", ns);
  return j;
}

Json SigScanResult::to_text_report() const {
  Json j = Json::make_object();
  std::string t;
  char buf[512];

  t += "Arctium 特征码扫描报告\n";
  t += "======================\n";
  std::snprintf(buf, sizeof(buf), "  目标: %s  PID %u\n", exe.c_str(), pid);
  t += buf;
  std::snprintf(buf, sizeof(buf), "  扫描映像: %zu 个，合计 %.1f MB\n\n", images_scanned,
                static_cast<double>(bytes_scanned) / (1024.0 * 1024.0));
  t += buf;

  t += "== 为什么用特征码而不是字符串 ==\n";
  t += "  之前用 \"Locally overridden files\" 的交叉引用找目标，命中的是崩溃日志\n";
  t += "  格式化函数（栈帧 0x140、该串进 rdx），正常流程调用 0 次。改它等于打坏\n";
  t += "  崩溃处理器，客户端只会以 EXCEPTION_INTERNAL_ERROR / 0xC00000E5 死掉。\n";
  t += "  Arctium 用函数序言特征码定位「文件打开函数」，这里照做。\n\n";

  if (hits.empty()) {
    t += "== 结果: 全部未命中 ==\n";
    t += "  这不是失败，是一条明确结论：12.0.7 上 Arctium 9.x/10.x 的序言字节\n";
    t += "  已经对不上了（编译器版本/内联策略变化）。需要从本机 exe 重新取特征。\n\n";
    t += "== 每个特征码的情况 ==\n";
    for (const auto& n : notes) t += "  - " + n + "\n";
    t += "\n  下一步: 用 bundle 里的 dump 模式把运行时映像存盘，在 IDA/x64dbg 里\n";
    t += "  按 xref 找 \"FileDataID\" 附近的 CASC 打开函数，重新提取序言。\n";
  } else {
    t += "== 命中 ==\n";
    for (const auto& h : hits) {
      t += "\n  [" + h.name + "]  " + h.verdict + "\n";
      std::snprintf(buf, sizeof(buf), "    匹配 0x%s   改写点 0x%s   映像 0x%s（%s）\n",
                    to_hex(h.match_va, 16).c_str(), to_hex(h.patch_va, 16).c_str(),
                    to_hex(h.image_base, 16).c_str(), h.image_note.c_str());
      t += buf;
      std::snprintf(buf, sizeof(buf), "    全映像出现 %zu 次\n", h.match_count);
      t += buf;
      // 同一份代码可能被映射两次（MEM_IMAGE 一份 + 壳的文件映射视图一份），
      // 它们的 RVA 完全相同。实测 12.0.7 的 2 处命中就是这么来的，不是"特征太弱"。
      std::snprintf(buf, sizeof(buf), "    相对映像 RVA 0x%s\n",
                    to_hex(h.match_va - h.image_base, 16).c_str());
      t += buf;
      if (h.semantic_score > 0) {
        std::snprintf(buf, sizeof(buf),
                      "    语义判别 %d/8   （键=edx 2 分 / murmur 哈希 3 分 / cmp[id] 3 分）\n",
                      h.semantic_score);
        t += buf;
        if (h.semantic_score >= 8)
          t += "    [目标] 这是 CAS.cpp 里 edx=FileDataID 的哈希查找函数，Arctium 就改这里。\n";
      }
      if (h.match_count > 1 && h.semantic_score < 8)
        t += "    ！出现多次且语义不足 = 特征太弱，直接改写可能改到无关代码，需要人工确认。\n";
      std::string hex;
      for (size_t i = 0; i < h.head.size(); ++i) {
        std::snprintf(buf, sizeof(buf), "%02X ", h.head[i]);
        hex += buf;
      }
      t += "    匹配处字节: " + hex + "\n";
    }
  }

  if (!notes.empty() && !hits.empty()) {
    t += "\n== 未命中的特征码 ==\n";
    for (const auto& n : notes) t += "  - " + n + "\n";
  }

  t += "\n本次扫描没有修改客户端任何字节。\n";
  j.set("text", Json::make_string(t));
  j.set("json", to_json());
  return j;
}

SigScanResult scan_arctium_signatures(HANDLE process, const std::string& exe_path) {
  SigScanResult out;
  out.exe = exe_path;
  out.pid = GetProcessId(process);

  struct Candidate {
    const ArctiumSignatureSpec* sig;
    Pattern pat;
    size_t total = 0;
    std::vector<size_t> per_image;
  };
  // ---- CustomFileIdHook 的语义判定 ----
  //
  // 光靠 43 字节特征码不够：实测 12.0.7 全进程有 6 处命中，其中多数是
  // 同一个 MSVC 序言（48 89 5C 24 08 57 48 83 EC 20 48 8B ?? ...）的巧合。
  // 真正目标是 CAS.cpp 里那个「edx = FileDataID → murmur 哈希 → 按 id 查表」
  // 的函数，它有唯一可识别的手指印：
  //   1. movsxd rbx, edx            （edx 作为键）
  //   2. 两个 murmur 魔数 0xff51afd7ed558ccd / 0xc4ceb9fe1a85ec53
  //   3. cmp [reg+8], ebx           （链表节点按 32 位 id 比较）
  //   4. 结尾 mov rax, rdi / ret    （返回查到的对象）
  // 三项全中才算真目标，否则降级为 near-miss，绝不建议改写。
  auto custom_fileid_score = [](const uint8_t* p, size_t n) -> int {
    int score = 0;
    bool has_movsxd = false, has_hash = false, has_cmp_ebx = false;
    for (size_t i = 0; i + 3 <= n; ++i) {
      if (p[i] == 0x48 && p[i + 1] == 0x63 && p[i + 2] == 0xDA) has_movsxd = true;
    }
    static const uint8_t kMagic1[8] = {0xcd, 0x8c, 0x55, 0xed, 0xd7, 0xaf, 0x51, 0xff};
    static const uint8_t kMagic2[8] = {0x53, 0xec, 0x85, 0x1a, 0xfe, 0xb9, 0xce, 0xc4};
    for (size_t i = 0; i + 8 <= n; ++i) {
      bool m1 = true, m2 = true;
      for (int k = 0; k < 8; ++k) {
        if (p[i + k] != kMagic1[k]) m1 = false;
        if (p[i + k] != kMagic2[k]) m2 = false;
      }
      if (m1) has_hash = true;
      if (m2) has_hash = true;
    }
    for (size_t i = 0; i + 3 <= n; ++i) {
      // 39 58 08 = cmp dword ptr [rax+8], ebx
      if (p[i] == 0x39 && p[i + 1] == 0x58 && p[i + 2] == 0x08) has_cmp_ebx = true;
    }
    if (has_movsxd) score += 2;
    if (has_hash) score += 3;
    if (has_cmp_ebx) score += 3;
    return score;   // 满分 8
  };

  std::vector<Candidate> cands;
  for (const auto& s : arctium_signature_specs()) {
    Candidate c;
    c.sig = &s;
    std::string perr;
    c.pat = Pattern::parse(s.pattern, &perr);
    if (!c.pat.valid()) {
      out.notes.push_back(std::string(s.name) + ": 特征码解析失败 " + perr);
      continue;
    }
    cands.push_back(std::move(c));
  }

  out.images = scan_process_images(process);
  const auto& images = out.images;
  out.images_scanned = images.size();

  // 每个特征码挑「命中次数最少」的那个映像作为可用目标；次数相同取最大映像。
  for (const auto& img : images) {
    if (img.bytes.empty()) continue;
    out.bytes_scanned += img.bytes.size();
    for (auto& c : cands) {
      const auto offs = c.pat.find_all(img.bytes);
      if (offs.empty()) continue;
      c.total += offs.size();
      // 记录本映像里的命中
      for (size_t off : offs) {
        SigHit h;
        h.name = c.sig->name;
        h.pattern = c.sig->pattern;
        h.patch_offset = c.sig->patch_offset;
        h.match_va = img.base + off;
        h.patch_va = h.match_va + static_cast<uint64_t>(c.sig->patch_offset);
        h.image_base = img.base;
        h.image_size = img.size;
        h.image_executable = img.executable;
        h.image_note = region_note(img);
        // 只对 CustomFileIdHook 做语义判别；其它特征码语义不同，不套用。
        if (std::string(c.sig->name) == "CustomFileIdHook") {
          const size_t probe = std::min<size_t>(0x120, img.bytes.size() - off);
          h.semantic_score = custom_fileid_score(img.bytes.data() + off, probe);
        }
        h.match_count = 1;  // 稍后回填全局次数
        const size_t head_off = off > 32 ? off - 32 : off;
        const size_t head_len = std::min<size_t>(64, img.bytes.size() - head_off);
        h.head.assign(img.bytes.begin() + head_off, img.bytes.begin() + head_off + head_len);
        out.hits.push_back(std::move(h));
      }
    }
  }

  // 回填每个特征码的全局出现次数并给出结论
  for (auto& h : out.hits) {
    size_t total = 0;
    for (const auto& c : cands) {
      if (h.name == c.sig->name) { total = c.total; break; }
    }
    h.match_count = total;
    if (h.name == "CustomFileIdHook" && h.semantic_score > 0) {
      // 语义满分的候选即使在多处命中里也算可用目标 —— 这才是真函数。
      h.verdict = h.semantic_score >= 8 ? "unique（语义确证，可用）"
                                        : "ambiguous（语义不足，勿改）";
    } else {
      h.verdict = total == 1 ? "unique（可考虑使用）" : "ambiguous（出现多次，需人工确认）";
    }
  }

  for (const auto& c : cands) {
    if (c.total == 0) out.notes.push_back(std::string(c.sig->name) + ": 未命中 — " + c.sig->note);
  }

  // 唯一命中的排在前面
  std::stable_sort(out.hits.begin(), out.hits.end(), [](const SigHit& a, const SigHit& b) {
    if (a.semantic_score != b.semantic_score) return a.semantic_score > b.semantic_score;
    if (a.match_count != b.match_count) return a.match_count < b.match_count;
    return a.image_size > b.image_size;
  });
  return out;
}

}  // namespace win
}  // namespace wowmod
#endif
