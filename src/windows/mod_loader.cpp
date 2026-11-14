// 模组加载器实现。见 mod_loader.hpp 的说明。
// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "windows/mod_loader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

#include "windows/arctium_patch.hpp"
#include "windows/arctium_sig.hpp"
#include "windows/detour.hpp"
#include "windows/fd_hook.hpp"
#include "windows/scan_images.hpp"
#include "wowmod/fileid_stub.hpp"

namespace fs = std::filesystem;

namespace wowmod {
namespace win {
namespace {

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
  return s.substr(a, b - a);
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// 把游戏相对路径规整成客户端期望的形式：
//   * 反斜杠 -> 正斜杠
//   * 全部小写（客户端内部按小写查表）
//   * 去掉开头的 ./ 或 /
// 注意：**不要去掉空格**。listfile 里有 31944 条路径本身就带空格
// （例如 "Character/NightElf/Female/NightElfFemaleNakedPelvisSkin00_ 14.blp"），
// 那是官方命名，去掉空格反而永远匹配不到。
std::string normalize_game_path(const std::string& in) {
  std::string s = in;
  std::replace(s.begin(), s.end(), '\\', '/');
  s = lower(s);
  while (s.rfind("./", 0) == 0) s = s.substr(2);
  while (!s.empty() && s[0] == '/') s = s.substr(1);
  return s;
}

}  // namespace

MappingLoadReport load_mappings(const std::string& wowmod_dir) {
  MappingLoadReport rep;
  const fs::path map_dir = fs::u8path(wowmod_dir) / "mappings";
  const fs::path files_dir = fs::u8path(wowmod_dir) / "files";

  std::error_code ec;
  if (!fs::is_directory(map_dir, ec)) {
    rep.error = "找不到 mappings 目录: " + map_dir.u8string();
    return rep;
  }
  if (!fs::is_directory(files_dir, ec)) {
    rep.error = "找不到 files 目录: " + files_dir.u8string();
    return rep;
  }

  // 同一个 FileDataID 只留第一个（映射文件可能互相覆盖，顺序不确定，
  // 与其让客户端随机命中，不如我们自己定死）
  std::map<uint64_t, size_t> seen;

  std::vector<fs::path> map_files;
  for (const auto& e : fs::directory_iterator(map_dir, ec)) {
    if (!e.is_regular_file(ec)) continue;
    if (lower(e.path().extension().u8string()) != ".txt") continue;
    map_files.push_back(e.path());
  }
  std::sort(map_files.begin(), map_files.end());  // 顺序稳定，便于复现

  for (const auto& mf : map_files) {
    std::ifstream in(mf, std::ios::binary);
    if (!in) {
      rep.error = "打不开 mappings 文件: " + mf.u8string();
      return rep;
    }
    ++rep.files_read;
    std::string line;
    while (std::getline(in, line)) {
      ++rep.lines_total;
      const std::string t = trim(line);
      if (t.empty() || t[0] == '#' || t[0] == ';') {
        ++rep.skipped_comment;
        continue;
      }
      const size_t semi = t.find(';');
      if (semi == std::string::npos) {
        ++rep.bad_lines;
        continue;
      }
      const std::string id_str = trim(t.substr(0, semi));
      const std::string game_path = trim(t.substr(semi + 1));
      if (id_str.empty() || game_path.empty()) {
        ++rep.bad_lines;
        continue;
      }
      char* end = nullptr;
      const unsigned long long id = std::strtoull(id_str.c_str(), &end, 10);
      if (!end || *end != '\0') {
        ++rep.bad_lines;
        continue;
      }
      ++rep.parsed;

      ModEntry e;
      e.file_data_id = static_cast<uint64_t>(id);
      e.game_path = normalize_game_path(game_path);
      // 本地文件按 mappings 里写的相对路径去 files\ 下找。
      // 注意这里用原始 game_path 而不是小写版本 —— Windows 不区分大小写，
      // 但大小写混合的真实文件名更利于人工核对。
      std::string rel = game_path;
      std::replace(rel.begin(), rel.end(), '\\', '/');
      while (rel.rfind("./", 0) == 0) rel = rel.substr(2);
      while (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
      e.local_path = (files_dir / fs::u8path(rel)).u8string();

      std::error_code fec;
      e.file_exists = fs::is_regular_file(fs::u8path(e.local_path), fec);

      if (!e.file_exists) {
        ++rep.missing_local;
        rep.missing.push_back(e);
        continue;
      }
      if (seen.count(e.file_data_id)) {
        // 同一 id 重复出现：保留第一条，后面的忽略（不报错，因为可能是
        // _HD / 非 _HD 两条不同的映射文件）
        continue;
      }
      seen[e.file_data_id] = rep.entries.size();
      rep.entries.push_back(e);
    }
  }

  if (rep.entries.empty()) {
    if (rep.error.empty()) {
      std::ostringstream os;
      os << "mappings 里没有任何一条可用的项（解析 " << rep.parsed << " 行, 磁盘缺失 "
         << rep.missing_local << " 个）";
      rep.error = os.str();
    }
    return rep;
  }
  return rep;
}

std::string format_mod_loader_report(const ModLoaderResult& r) {
  std::ostringstream os;
  os << "=========== 模组加载器（Arctium 机制完整版）===========\n";
  os << "\n[第一半] NoJump 分支补丁\n";
  if (r.branch_patched)
    os << "  已打 " << r.branch_count << " 条（je rel32 -> 00 00 00 00）\n";
  else
    os << "  未完成\n";

  os << "\n[第二半] FileDataID -> 本地路径 查表跳板\n";
  if (r.hook_installed) {
    char b[256];
    std::snprintf(b, sizeof(b), "  已安装于 0x%llX\n",
                  static_cast<unsigned long long>(r.hook_target));
    os << b;
    std::snprintf(b, sizeof(b), "  id 表 0x%llX / 字符串块 0x%llX\n",
                  static_cast<unsigned long long>(r.id_table_va),
                  static_cast<unsigned long long>(r.string_blob_va));
    os << b;
    std::snprintf(b, sizeof(b), "  跳板 0x%llX / trampoline 0x%llX\n",
                  static_cast<unsigned long long>(r.stub_va),
                  static_cast<unsigned long long>(r.trampoline_va));
    os << b;
  } else {
    os << "  未安装\n";
  }

  os << "\n[数据] 可用 " << r.entries_loaded << " 项，磁盘缺失 " << r.entries_missing << " 项\n";

  if (!r.steps.empty()) {
    os << "\n步骤:\n";
    for (const auto& s : r.steps) os << "  " << s << "\n";
  }
  if (!r.ok && !r.error.empty()) os << "\n[失败] " << r.error << "\n";
  return os.str();
}

ModLoaderResult install_mod_loader(HANDLE process, const std::string& wowmod_dir,
                                   uint32_t wait_ms) {
  ModLoaderResult r;
  auto step = [&](const std::string& s) {
    r.steps.push_back(s);
    std::printf("  %s\n", s.c_str());
    std::fflush(stdout);
  };

  // ---- 1. 等代码解密 ----
  //
  // 12.0.7 的 .text 是按页惰性解密的：只有游戏真正执行到的页才是明文。
  // 在密文上扫描得到的命中是随机字节（实测同一特征码三次跑出 10/2/1 处命中，
  // 且地址连主模块范围都不在）。所以必须等到明文比例足够才开始找。
  const unsigned kMinPlainPct = 50;
  bool ready = false;
  size_t best_low = 0, last_checked = 0;
  int stable = 0;
  const DWORD t0 = GetTickCount();
  for (int i = 0; i < 400; ++i) {
    const auto probe = dump_module_full(process, "", "");
    if (probe.text_checked) {
      const size_t pct = 100 * probe.text_low_entropy / probe.text_checked;
      if (i % 3 == 0) {
        std::printf("  等待代码解密... 明文页 %zu/%zu = %zu%% (需要 >= %u%%)\n",
                    probe.text_low_entropy, probe.text_checked, pct, kMinPlainPct);
        std::fflush(stdout);
      }
      last_checked = probe.text_checked;
      if (probe.text_low_entropy > best_low) {
        best_low = probe.text_low_entropy;
        stable = 0;
      } else {
        ++stable;
      }
      if (pct >= kMinPlainPct && stable >= 2) {
        ready = true;
        break;
      }
    }
    if (GetTickCount() - t0 > wait_ms) break;
    ::Sleep(1000);
  }
  if (!ready) {
    const size_t pct = last_checked ? 100 * best_low / last_checked : 0;
    r.error = "代码未解密到可用程度（明文 " + std::to_string(best_low) + "/" +
              std::to_string(last_checked) + " = " + std::to_string(pct) +
              "%，需要 >= " + std::to_string(kMinPlainPct) + "%）。在密文上扫描不可信，已拒绝。";
    return r;
  }
  step("代码已解密到可用程度（明文 " + std::to_string(best_low) + " 页）");

  // ---- 2. 读数据 ----
  const auto data = load_mappings(wowmod_dir);
  if (data.entries.empty()) {
    r.error = data.error.empty() ? "没有可用的映射" : data.error;
    return r;
  }
  r.entries_loaded = data.entries.size();
  r.entries_missing = data.missing_local;
  step("读到 " + std::to_string(data.files_read) + " 个 mappings 文件, 可用 " +
       std::to_string(data.entries.size()) + " 项" +
       (data.missing_local ? "（磁盘缺失 " + std::to_string(data.missing_local) + " 项，已跳过）"
                           : ""));
  if (data.bad_lines)
    step("警告: " + std::to_string(data.bad_lines) + " 行格式不对，已跳过");

  // ---- 3. 找 hook 点 ----
  const auto sig = scan_arctium_signatures(process, "");
  uint64_t target = 0;
  int best = 0;
  bool best_rx = false;
  for (const auto& h : sig.hits) {
    if (h.name != "CustomFileIdHook") continue;
    std::printf("    候选 0x%llX  语义 %d/8  %s\n",
                static_cast<unsigned long long>(h.match_va), h.semantic_score,
                h.has_rx ? "可执行" : "【不可执行】");
    const bool better = (h.semantic_score > best) ||
                        (h.semantic_score == best && h.has_rx && !best_rx);
    if (better && h.has_rx) {
      best = h.semantic_score;
      best_rx = h.has_rx;
      target = h.match_va;
    }
  }
  if (!target || !best_rx) {
    r.error = "CustomFileIdHook 没找到可执行目标（最高语义分 " + std::to_string(best) +
              "/8）。代码可能仍未解密到那一段。";
    return r;
  }
  step("hook 目标 0x" + to_hex(target, 16) + "（语义分 " + std::to_string(best) + "/8）");

  // ---- 4. 装查表跳板（第二半）----
  {
    InstallRequest req;
    req.hook_target = target;
    // Arctium 的 stub 从 edx 取 FileDataID。
    // 但被覆盖的那条指令是 mov rdi, rcx —— 说明调用点传参用 rcx/rdi，
    // 返回值用 rdi（不是 rax）。所以这里两件事分开：
    //   id 从 rdx 取（FileDataID 恒在 edx，已由 20 条实测记录确证）
    //   命中时把路径指针放进 rdi（调用点真正读取的寄存器）
    req.id_register = "rdx";
    req.return_register = "rdi";
    // 必须至少覆盖 13 字节（Arctium 的 hook 长度），
    // 这个函数的指令边界正好是 16 字节，所以 detour 会搬 16 字节。
    req.min_cover = 13;
    req.entries.reserve(data.entries.size());
    for (const auto& e : data.entries) req.entries.emplace_back(e.file_data_id, e.game_path);

    FileIdHook hook;
    hook.set_process(process);
    InstallReport irep;
    if (!hook.install(process, req, &irep)) {
      r.error = "安装查表跳板失败: " + irep.error;
      for (const auto& s : irep.steps) r.steps.push_back(s);
      return r;
    }
    for (const auto& s : irep.steps) step(s);
    r.hook_installed = true;
    r.hook_target = target;
    r.id_table_va = irep.id_table_va;
    r.string_blob_va = irep.string_blob_va;
    r.stub_va = irep.stub_va;
    r.trampoline_va = irep.trampoline_va;
  }

  // ---- 5. 打 NoJump（第一半）----
  {
    auto rep = plan_branch_patches(process, {});
    if (!rep.ok) {
      // 第二半已经装上了，第一半失败就意味着「客户端不会去查表」。
      // 这比不装更糟（跳板白占内存、行为没变），所以如实报告。
      r.error = "查表跳板已装，但 NoJump 分支补丁失败: " + rep.error;
      return r;
    }
    if (!apply_branch_patches(process, &rep)) {
      r.error = "查表跳板已装，但 NoJump 写入失败: " + rep.error;
      return r;
    }
    r.branch_patched = true;
    r.branch_count = rep.applied_count;
    step("NoJump 已打 " + std::to_string(rep.applied_count) + " 条");
  }

  r.ok = true;
  return r;
}

}  // namespace win
}  // namespace wowmod
#endif
