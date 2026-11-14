// 映像离线分析实现。
// SPDX-License-Identifier: MIT
#include "wowmod/xref.hpp"

#include <chrono>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

#include "wowmod/util.hpp"
#include "wowmod/x64_decode.hpp"

namespace wowmod {

namespace {

uint32_t rd32(const uint8_t* p) {
  uint32_t v;
  std::memcpy(&v, p, 4);
  return v;
}
int32_t rdi32(const uint8_t* p) {
  int32_t v;
  std::memcpy(&v, p, 4);
  return v;
}

// 判断 off 处是否是 `48/4C 8D/8B xx disp32` 形状的 RIP 相对指令，返回长度。
// 只接受这两种最常见的形态（编译器为字符串/全局变量取地址时几乎只用它们）。
bool match_rip_insn(const uint8_t* p, size_t avail, size_t lead) {
  if (avail < lead + 6) return false;
  const uint8_t op = p[lead];
  const uint8_t modrm = p[lead + 1];
  if (op != 0x8D && op != 0x8B && op != 0x89) return false;
  return (modrm & 0xC7) == 0x05;  // mod=00, rm=101 -> RIP+disp32
}

}  // namespace

std::vector<size_t> find_bytes(const ImageView& img, const std::string& needle, bool utf16,
                               size_t max_hits, double max_seconds) {
  std::vector<size_t> hits;
  if (!img.valid() || needle.empty()) return hits;
  const auto t0 = std::chrono::steady_clock::now();
  auto budget_left = [&]() {
    if (max_seconds <= 0.0) return true;
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() <
           max_seconds;
  };
  std::string pat;
  if (utf16) {
    pat.reserve(needle.size() * 2);
    for (char c : needle) {
      pat.push_back(c);
      pat.push_back('\0');
    }
  } else {
    pat = needle;
  }
  if (pat.size() > img.size) return hits;
  const uint8_t* base = img.data;
  const size_t limit = img.size - pat.size();
  size_t scan_check = 0;
  // 用 memchr 找首字节（glibc 里是 SIMD），比逐字节比较快一个数量级。
  const uint8_t first = static_cast<uint8_t>(pat[0]);
  size_t i = 0;
  while (i <= limit) {
    const void* p = std::memchr(base + i, first, limit - i + 1);
    if (!p) break;
    i = static_cast<size_t>(static_cast<const uint8_t*>(p) - base);
    if (std::memcmp(base + i, pat.data(), pat.size()) == 0) {
      hits.push_back(i);
      if (hits.size() >= max_hits) break;
    }
    if (((++scan_check) & 0xFFFF) == 0 && !budget_left()) break;
    ++i;
  }
  return hits;
}

// 单次全盘扫描，同时为一组目标地址找 RIP 相对引用。
// 为什么需要这个：分析阶段有「标记数 × 字符串命中数」个目标，每个目标各扫
// 一遍 108MB 映像 = 上百次全盘扫描。合并成一次之后耗时与目标数无关。
std::map<uint64_t, std::vector<CodeRef>> find_code_refs_to_many(
    const ImageView& img, const std::vector<uint64_t>& targets, size_t max_hits_per_target,
    double max_seconds) {
  std::map<uint64_t, std::vector<CodeRef>> out;
  if (!img.valid() || targets.empty()) return out;
  const auto t_start = std::chrono::steady_clock::now();
  auto budget_left = [&]() -> bool {
    if (max_seconds <= 0.0) return true;
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count() <
           max_seconds;
  };
  // 关键换算：编译器生成的 RIP 相对引用满足
  //     disp32 = target_va - insn_end_va        (mod 2^32)
  // insn_end_va = base + i + insn_len，而 target_va = base + target_off
  //   => target_off = i + insn_len + disp32     (mod 2^32)
  // 所以按「目标在映像内的偏移」建索引，扫描时用 i+insn_len+disp 去查表，
  // 一次比较即可粗筛，不需要为每个目标各扫一遍。
  std::map<uint32_t, std::vector<uint64_t>> want;
  for (uint64_t t : targets) {
    if (t < img.base_va) continue;
    const uint64_t off = t - img.base_va;
    if (off >= img.size) continue;
    auto& v = want[static_cast<uint32_t>(off)];
    if (std::find(v.begin(), v.end(), t) == v.end()) v.push_back(t);
  }
  // 扫描 RIP 相对取址指令：8D/8B/89 /r，modrm 的 mod=00 rm=101。
  // 指令可能带一个 REX 前缀（48 8D 0D ...），也可能不带（8D 0D ...）。
  // 指令长度 = 6（无 REX）或 7（有 REX），disp32 都在 opcode+2 处。
  //
  //   target_off = insn_start + insn_len + disp32   (mod 2^32)
  //
  // 用「目标偏移」做哈希键，一次遍历即可解出全部目标，与目标数量无关。
  size_t budget_check = 0;
  size_t done = 0;
  const size_t total_targets = want.size();
  const size_t limit = img.size >= 7 ? img.size - 7 : 0;
  for (size_t i = 0; i <= limit; ++i) {
    if ((++budget_check & 0xFFFFF) == 0 && !budget_left()) break;
    const uint8_t op = img.data[i];
    if (op != 0x8D && op != 0x8B && op != 0x89) continue;
    if ((img.data[i + 1] & 0xC7) != 0x05) continue;
    const uint32_t disp = rdi32(img.data + i + 2);
    // 有 REX 前缀时优先按「带前缀」解释（指令起点在 i-1）；
    // 若那条不成立，再按「REX 前一个字节属于上一条指令」解释（起点在 i）。
    for (int rex = 1; rex >= 0; --rex) {
      if (rex) {
        if (i == 0) continue;
        if ((img.data[i - 1] & 0xF0) != 0x40) continue;  // 前一个字节必须是 REX
      }
      const size_t start = i - static_cast<size_t>(rex);
      const size_t len = 6 + static_cast<size_t>(rex);
      const uint32_t cand_off = static_cast<uint32_t>(start + len) + disp;
      auto it = want.find(cand_off);
      if (it == want.end()) continue;
      bool matched = false;
      for (uint64_t target_va : it->second) {
        if (static_cast<uint32_t>(target_va - img.base_va) != cand_off) continue;
        auto& bucket = out[target_va];
        if (bucket.size() >= max_hits_per_target) continue;
        CodeRef r;
        r.at = start;  // 指令起点（含 REX 前缀），与反汇编器的地址一致
        r.target_va = target_va;
        r.target_off = cand_off;
        r.form = (op == 0x8D) ? "lea" : (op == 0x8B ? "mov" : "mov-store");
        bucket.push_back(r);
        matched = true;
        if (bucket.size() >= max_hits_per_target) ++done;
        break;
      }
      if (matched) break;  // 同一条指令不再按另一种前缀解释
    }
    if (total_targets && done >= total_targets) break;
  }
  return out;
}

std::vector<CodeRef> find_code_refs_to(const ImageView& img, uint64_t target_va,
                                      size_t max_hits, double max_seconds) {
  auto m = find_code_refs_to_many(img, {target_va}, max_hits, max_seconds);
  auto it = m.find(target_va);
  return it == m.end() ? std::vector<CodeRef>{} : it->second;
}

size_t find_function_start(const ImageView& img, size_t pos, size_t max_back) {
  if (!img.valid() || pos >= img.size) return SIZE_MAX;
  const size_t lo = pos > max_back ? pos - max_back : 0;

  // 1) 向前找连续的填充（0xCC / 0x90 / 0x00）边界，边界之后就是起点。
  for (size_t i = pos; i > lo; --i) {
    const uint8_t prev = img.data[i - 1];
    if (prev == 0xCC || prev == 0x00) {
      // 要求前面还有至少 3 个同样的填充，避免把立即数里的 0x00 当成对齐
      size_t run = 0;
      for (size_t k = i; k > lo && (img.data[k - 1] == 0xCC || img.data[k - 1] == 0x00); --k) ++run;
      if (run >= 3) return i;
    }
  }

  // 2) 序言特征：push rbp / mov rbp,rsp / sub rsp,imm / push 多个寄存器
  static const std::vector<std::vector<uint8_t>> prologues = {
      {0x48, 0x89, 0x5C, 0x24},              // mov [rsp+x], rbx
      {0x48, 0x89, 0x4C, 0x24},              // mov [rsp+x], rcx
      {0x40, 0x53},                          // push rbx (REX)
      {0x48, 0x83, 0xEC},                    // sub rsp, imm8
      {0x48, 0x81, 0xEC},                    // sub rsp, imm32
      {0x55},                                // push rbp
      {0x48, 0x8B, 0xC4},                    // mov rax, rsp
      {0x4C, 0x8B, 0xDC},                    // mov r11, rsp
      {0x48, 0x8B, 0xD1},                    // mov rdx, rcx
  };
  // 3) ret 之后也是常见起点（x64 编译器常把 ret 直接接下一个函数）
  for (size_t i = pos; i > lo; --i) {
    const uint8_t b = img.data[i - 1];
    if (b == 0xC3 || b == 0xC2) {
      // ret/ret imm16 之后
      size_t cand = i + (b == 0xC2 ? 2 : 0);
      if (cand < pos) return cand;
    }
    for (const auto& pr : prologues) {
      if (i >= pr.size() && std::memcmp(img.data + i - pr.size(), pr.data(), pr.size()) == 0) {
        return i - pr.size();
      }
    }
  }
  return SIZE_MAX;
}

std::vector<ShownInsn> disassemble_window(const ImageView& img, size_t pos, size_t max_bytes) {
  std::vector<ShownInsn> out;
  if (!img.valid() || pos >= img.size) return out;
  size_t p = pos;
  const size_t end = std::min(img.size, pos + max_bytes);
  while (p < end) {
    const x64::DecodedInsn d = x64::decode(img.data + p, img.size - p);
    if (d.length == 0) break;
    ShownInsn s;
    s.rva = p;
    s.bytes.assign(img.data + p, img.data + p + d.length);
    s.is_rip_relative = d.is_rip_relative;
    s.is_jump = d.is_jump;
    char buf[160];
    std::string hexs;
    for (uint8_t b : s.bytes) {
      char h[4];
      std::snprintf(h, sizeof(h), "%02x ", b);
      hexs += h;
    }
    if (d.is_rip_relative) {
      const uint64_t tgt = img.va_of(p + d.length) + static_cast<int64_t>(d.rip_disp);
      std::snprintf(buf, sizeof(buf), "%-40s ; -> %s", hexs.c_str(), to_hex(tgt, 16).c_str());
    } else {
      std::snprintf(buf, sizeof(buf), "%s", hexs.c_str());
    }
    s.text = buf;
    out.push_back(s);
    p += d.length;
  }
  return out;
}

HookSitePlan plan_hook_site(const ImageView& img, size_t rva, size_t min_bytes) {
  HookSitePlan plan;
  plan.rva = rva;
  if (!img.valid() || rva >= img.size) {
    plan.reason = "地址超出映像范围";
    return plan;
  }
  const size_t copy_len = x64::find_safe_split(img.data, img.size, rva, min_bytes);
  if (copy_len == 0) {
    plan.reason = "无法在该地址找到完整指令边界（解码失败或吞噬过多）";
    plan.prologue = disassemble_window(img, rva, 32);
    return plan;
  }
  plan.copy_len = copy_len;
  plan.prologue = disassemble_window(img, rva, copy_len + 16);

  // 检查搬运的指令里有没有相对位移
  size_t p = rva;
  while (p < rva + copy_len) {
    const x64::DecodedInsn d = x64::decode(img.data + p, img.size - p);
    if (d.length == 0) {
      plan.reason = "搬运区间内解码失败";
      return plan;
    }
    if (d.is_rip_relative) plan.has_rip_relative = true;
    if (d.is_jump) plan.has_jump = true;
    p += d.length;
  }
  // 用假想 trampoline 地址验证 rel8 跳转能否重算（rel8 一旦超距就要改写指令，
  // 这里先按最坏情况拒绝：包含 rel8 跳转的 hook 点不可用）
  if (plan.has_jump) {
    size_t q = rva;
    while (q < rva + copy_len) {
      const x64::DecodedInsn d = x64::decode(img.data + q, img.size - q);
      const uint8_t op = img.data[q];
      if (d.is_jump && (((op >= 0x70 && op <= 0x7F)) || op == 0xEB)) {
        plan.reason = "搬运区间包含 rel8 跳转，无法安全重定位";
        return plan;
      }
      q += d.length;
    }
  }
  plan.relocatable = true;
  plan.ok = true;
  plan.reason = "可用：覆盖 " + std::to_string(copy_len) + " 字节完整指令";
  return plan;
}

// ---------------------------------------------------------------------------

std::vector<IdLookupCandidate> scan_id_lookup_candidates(const ImageView& img, size_t max_results,
                                                         double max_seconds) {
  std::vector<IdLookupCandidate> out;
  if (!img.valid()) return out;

  // 时间预算：100MB+ 映像逐字节扫描可能几十秒。到点就返回已有结果。
  const auto t_start = std::chrono::steady_clock::now();
  auto budget_left = [&]() -> bool {
    if (max_seconds <= 0.0) return true;
    const double sec =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    return sec < max_seconds;
  };

  // 扫描 `cmp r/m32, r32`（39 /r）且 r/m 使用 base+index*scale 的寻址。
  size_t budget_check = 0;
  for (size_t i = 0; i + 8 < img.size; ++i) {
    // 每 64KB 检查一次时间，开销可忽略
    if ((++budget_check & 0xFFFF) == 0 && !budget_left()) break;
    size_t p = i;
    // 可选 REX
    bool rex = false;
    if ((img.data[p] & 0xF0) == 0x40) {
      rex = true;
      ++p;
    }
    const uint8_t op = img.data[p];
    if (op != 0x39 && op != 0x3B) continue;  // cmp r/m32,r32 / cmp r32,r/m32
    const uint8_t modrm = img.data[p + 1];
    if ((modrm >> 6) == 3) continue;         // 必须是内存操作数
    if ((modrm & 7) != 4) continue;          // 需要 SIB
    const uint8_t sib = img.data[p + 2];
    const int scale_bits = sib >> 6;
    const int index = (sib >> 3) & 7;
    const int base = sib & 7;
    if (index == 4) continue;                // 无索引寄存器 -> 不是数组查找
    if (base == 5 && (modrm >> 6) == 0) continue;  // disp32 绝对地址，不是数组基址
    const int scale = 1 << scale_bits;
    if (scale != 4 && scale != 8) continue;  // FileDataID 表项 4 或 8 字节

    // 往回找函数起点
    const size_t fn = find_function_start(img, i, 0x1200);
    if (fn == SIZE_MAX) continue;
    // 起点离比较指令太近，说明边界判定不可靠（常见于误命中指令中间）
    if (i - fn < 0x20) continue;
    // 函数体内必须有 ret（否则可能落在数据/桩代码里）
    {
      bool has_ret = false;
      size_t q = i;
      for (int n = 0; n < 900 && q < img.size; ++n) {
        const x64::DecodedInsn d = x64::decode(img.data + q, img.size - q);
        if (d.length == 0) break;
        if (d.is_ret) { has_ret = true; break; }
        q += d.length;
      }
      if (!has_ret) continue;
    }

    // 评分：函数里是否还有其它类似比较（线性查找循环）、id 符号检查
    int score = 10;
    std::string ev;
    ev += "cmp 使用 [base + idx*" + std::to_string(scale) + "]";
    ev += ", base=r" + std::to_string(base + (rex ? 8 : 0)) +
          ", idx=r" + std::to_string(index + (rex ? 8 : 0));

    // 附近是否有 add rXX, 1 / inc（循环自增）以及 jne/jb 回跳
    size_t q = fn;
    int compares = 0, back_jumps = 0;
    for (int n = 0; n < 600 && q < img.size; ++n) {
      const x64::DecodedInsn d = x64::decode(img.data + q, img.size - q);
      if (d.length == 0) break;
      const uint8_t b0 = img.data[q];
      const uint8_t b1 = (q + 1 < img.size) ? img.data[q + 1] : 0;
      if ((b0 & 0xF0) == 0x40) {
        if (b1 == 0x39 || b1 == 0x3B) ++compares;
      } else if (b0 == 0x39 || b0 == 0x3B) {
        ++compares;
      }
      // 回跳：jcc rel8/disp32 目标小于当前位置
      if (d.is_jump) {
        int64_t delta = 0;
        size_t po = q;
        while (po < img.size && ((img.data[po] & 0xF0) == 0x40)) ++po;
        const uint8_t o = img.data[po];
        if (o == 0x0F && (po + 1 < img.size)) {
          delta = static_cast<int8_t>(0);  // 0F 8x 用 disp32，下面单独处理
          if (po + 6 <= img.size) delta = rdi32(img.data + q + d.length - 4);
        } else if ((o >= 0x70 && o <= 0x7F) || o == 0xEB) {
          delta = static_cast<int8_t>(img.data[q + d.length - 1]);
        }
        if (delta < 0) ++back_jumps;
      }
      q += d.length;
    }
    if (compares >= 2) score += 15;
    if (back_jumps >= 1) score += 20;
    if (back_jumps == 0 && compares < 2) score -= 10;

    IdLookupCandidate c;
    c.rva = fn;
    c.cmp_rva = i;
    c.score = score;
    c.scale = scale;
    // 在没有 ABI 证据前不猜死寄存器名，只报告形状
    c.id_register = "";
    c.evidence = ev;
    c.window = disassemble_window(img, i >= 16 ? i - 16 : 0, 48);
    out.push_back(std::move(c));
    i += 2;
  }

  std::sort(out.begin(), out.end(),
            [](const IdLookupCandidate& a, const IdLookupCandidate& b) { return a.score > b.score; });
  if (out.size() > max_results) out.resize(max_results);
  return out;
}

std::string render_candidates(const std::vector<IdLookupCandidate>& cands) {
  std::string s;
  char buf[512];
  s += "发现 " + std::to_string(cands.size()) + " 个 FileDataID 查找候选（按可信度排序）\n";
  for (size_t i = 0; i < cands.size(); ++i) {
    const auto& c = cands[i];
    std::snprintf(buf, sizeof(buf),
                  "[%zu] score=%d fn=+0x%zx cmp=+0x%zx scale=%d  %s\n", i, c.score, c.rva,
                  c.cmp_rva, c.scale, c.evidence.c_str());
    s += buf;
    for (const auto& w : c.window) {
      std::snprintf(buf, sizeof(buf), "      +0x%zx: %s\n", w.rva, w.text.c_str());
      s += buf;
    }
  }
  s += "\n注意：这些只是结构候选。真正确认需要在运行期观察实参（id 在哪个寄存器、\n"
       "返回的是路径/缓冲区还是句柄）。本项目不会在未经确认时自动打补丁。\n";
  return s;
}

}  // namespace wowmod
