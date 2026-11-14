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

#include "windows/arctium_clone.hpp"
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

// Arctium 的 hook 长度（13 字节）。放在这里而不是文件作用域，
// 因为 arctium::kHookLen 在该命名空间里。
constexpr size_t kArctiumHookLen = wowmod::arctium::kHookLen;

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
                                   uint32_t wait_ms, StubKind kind) {
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

  // ---- 3b. 先【规划】NoJump（只读，不写）----
  //
  // 用户实测踩过：跳板装成功、NoJump 失败，结果是「改了内存但行为没变」——
  // 比什么都不做更糟，因为占用了 id 表/字符串块并且 hook 了文件加载主函数。
  // 所以顺序改成：先把 NoJump 的规划做完（纯读），确认能打，再动第二半。
  std::map<std::string, uint32_t> by_rva;
  for (const auto& s2 : arctium_signature_specs()) {
    if (s2.name != "LoadByFileIdAlternate" && s2.name != "LoadByFilePathAlternate") continue;
    if (s2.known_rva && s2.known_build == 68974) by_rva[s2.name] = s2.known_rva;
  }
  if (!by_rva.empty()) {
    std::string names;
    for (const auto& kv : by_rva) {
      names += (names.empty() ? "" : ", ");
      names += kv.first + "=0x" + to_hex(kv.second, 0);
    }
    step("按离线确证 RVA 点名: " + names);
  }
  BranchPatchReport branch_plan;
  {
    branch_plan = plan_branch_patches(process, by_rva);
    if (!branch_plan.ok) {
      r.error = "NoJump 无法安全安装: " + branch_plan.error +
                "（第 4 步之前就停止，没有改动客户端任何字节）";
      return r;
    }
    step("NoJump 规划通过 " + std::to_string(branch_plan.plannable) + " 条");
  }

  // ---- 4. 装查表跳板（第二半）----
  //
  // 两条路径：
  //   kArctium : 逐字节照抄 Arctium（12 字节表、50 字节固定 stub、
  //              13 字节 hook、跳板 = stub + 原指令 + 跳回）
  //   kNative  : 本项目生成器（16 字节表、命中直接 ret、未命中跳 trampoline）
  // 默认走 kArctium，因为用户要的是「Arctium 能做什么就做到什么」。
  if (kind == StubKind::kArctium) {
    // 4a. 序列化表（12 字节/项）
    std::vector<std::pair<uint64_t, std::string>> entries;
    entries.reserve(data.entries.size());
    for (const auto& e : data.entries) entries.emplace_back(e.file_data_id, e.game_path);
    auto ser = arctium::serialize_arctium_mappings(entries);
    if (ser.table.empty() || ser.strings.empty()) {
      r.error = "序列化映射表失败（表或字符串块为空）";
      return r;
    }

    // 4b. 两块内存：idAlloc(count*12) / stringAlloc(strings.size())
    RemoteBlock id_blk(process, ser.table.size(), PAGE_READWRITE);
    RemoteBlock str_blk(process, ser.strings.size(), PAGE_READWRITE);
    if (!id_blk.ok() || !str_blk.ok()) {
      r.error = "VirtualAllocEx 失败（id 表或字符串块）";
      return r;
    }
    const uint64_t id_va = reinterpret_cast<uint64_t>(id_blk.addr());
    const uint64_t str_va = reinterpret_cast<uint64_t>(str_blk.addr());

    // 4c. 路径字段改成绝对地址后再整体写入
    arctium::patch_string_addresses(&ser, str_va);
    std::string werr;
    if (!write_remote(process, str_va, ser.strings.data(), ser.strings.size(), &werr, false) ||
        !write_remote(process, id_va, ser.table.data(), ser.table.size(), &werr, false)) {
      r.error = "写入映射表失败: " + werr;
      return r;
    }
    // 两块都收紧成只读（Arctium 原样）
    DWORD oldp = 0;
    VirtualProtectEx(process, id_blk.addr(), id_blk.size(), PAGE_READONLY, &oldp);
    VirtualProtectEx(process, str_blk.addr(), str_blk.size(), PAGE_READONLY, &oldp);
    step("映射表写入完成: " + std::to_string(ser.count) + " 项, 12 字节/项, id 表 @0x" +
         to_hex(id_va, 16) + ", 字符串块 @0x" + to_hex(str_va, 16));

    // 4d. 读 hook 点 13 字节原始指令（Arctium: memory.Read(hookAddress, 13)）
    std::vector<uint8_t> orig(kArctiumHookLen, 0);
    if (!read_remote(process, target, orig.data(), orig.size(), &werr)) {
      r.error = "读取 hook 点 13 字节失败: " + werr;
      return r;
    }

    // 4e. 跳板 = 50 字节 stub + 13 字节原指令 + 13 字节跳回
    RemoteBlock tramp(process, 50 + 13 + 13, PAGE_EXECUTE_READWRITE);
    if (!tramp.ok()) {
      r.error = "VirtualAllocEx(跳板) 失败";
      return r;
    }
    const uint64_t tramp_va = reinterpret_cast<uint64_t>(tramp.addr());

    std::vector<uint8_t> code = arctium::build_arctium_stub(id_va, static_cast<uint32_t>(ser.count));
    code.insert(code.end(), orig.begin(), orig.end());
    auto back = arctium::build_hook_jump(target + kArctiumHookLen);
    code.insert(code.end(), back.begin(), back.end());
    if (!write_remote(process, tramp_va, code.data(), code.size(), &werr)) {
      r.error = "写入跳板失败: " + werr;
      return r;
    }
    DWORD oldx = 0;
    VirtualProtectEx(process, tramp.addr(), tramp.size(), PAGE_EXECUTE_READ, &oldx);
    step("跳板写入完成: " + std::to_string(code.size()) + " 字节 @0x" + to_hex(tramp_va, 16) +
         "（50 stub + 13 原指令 + 13 跳回）");

    // 4f. 在 hook 点写 13 字节跳转（Arctium 的 hookInstructions 原样）
    auto hook = arctium::build_hook_jump(tramp_va);
    DWORD oldh = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(target), hook.size(),
                     PAGE_EXECUTE_READWRITE, &oldh);
    if (!write_remote(process, target, hook.data(), hook.size(), &werr)) {
      r.error = "写入 hook 跳转失败: " + werr;
      return r;
    }
    VirtualProtectEx(process, reinterpret_cast<void*>(target), hook.size(), oldh, &oldh);
    FlushInstructionCache(process, reinterpret_cast<void*>(target), hook.size());
    step("hook 已安装: 0x" + to_hex(target, 16) + " -> 0x" + to_hex(tramp_va, 16));

    r.hook_installed = true;
    r.hook_target = target;
    r.id_table_va = id_va;
    r.string_blob_va = str_va;
    r.stub_va = tramp_va;
    r.trampoline_va = target + kArctiumHookLen;
  } else {
    InstallRequest req;
    req.hook_target = target;
    // ---- 寄存器选择的依据（全部来自用户上传的真实字节离线反汇编）----
    //
    // 序言:
    //   1433E06A0  mov [rsp+8], rbx
    //   1433E06A5  push rdi
    //   1433E06A6  sub rsp, 0x20
    //   1433E06AA  mov rdi, rcx      <- 第一个参数保存到 rdi（之后被 lea 覆盖）
    // 结论:
    //   * FileDataID 在【第二个参数】rdx/edx（同上一函数 0x33e0620 的 [rsp+8] 双参惯例）
    //   * rdi 不是返回值寄存器，它只是第一个参数的暂存
    //
    // 返回路径:
    //   1433E074B  mov rbx, [rsp+0x30]
    //   1433E0750  mov rax, rdi     <- 函数自己的返回值是【从 rdi 搬进 rax】
    //   1433E0758  ret
    // 所以函数对外的返回值确实在 rax，内容是"某个对象指针"。
    //
    // 我们要给调用方的是「本地文件路径字符串指针」。它必须从 rax 返回，
    // 而且【绝不能进函数体】—— 进了就会走 push rdi / mov [rsp+8],rbx 之后
    // 的收尾逻辑，栈会多退 8、rbx 会被覆盖，直接崩溃（这正是上次
    // EXCEPTION_INTERNAL_ERROR 的成因）。
    // stub 命中时直接 ret，不执行任何序言/收尾：此时 rsp 还是调用方 call
    // 之后的原值，ret 正好返回到调用点。
    req.id_register = "rdx";
    req.return_register = "rax";
    // 覆盖 13 字节（Arctium 的 hook 长度）。这个序言 13 字节正好是指令边界，
    // 下一条指令 1433E06AD `lea rcx,[rip+...]` 从 +13 开始。
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

  // ---- 5. 应用已规划好的 NoJump（第一半）----
  if (!apply_branch_patches(process, &branch_plan)) {
    r.error = "NoJump 写入失败: " + branch_plan.error +
              "（查表跳板已装，但第一半没成 —— 请重启客户端后重试）";
    return r;
  }
  r.branch_patched = true;
  r.branch_count = branch_plan.applied_count;
  step("NoJump 已打 " + std::to_string(branch_plan.applied_count) + " 条");

  r.ok = true;
  return r;
}

}  // namespace win
}  // namespace wowmod
#endif
