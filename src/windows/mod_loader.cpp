// 模组加载器实现。见 mod_loader.hpp 的说明。
// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "windows/mod_loader.hpp"
#include "windows/process_suspend.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

#include "windows/anticrash.hpp"
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


}  // namespace

// files 目录的绝对路径。Arctium 存进字符串块的就是这个前缀 + 相对路径。
std::string files_dir_for(const std::string& wowmod_dir) {
  std::error_code ec;
  fs::path p = fs::u8path(wowmod_dir) / "files";
  const fs::path abs = fs::absolute(p, ec);
  if (ec) return p.u8string();
  return abs.u8string();
}

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

  os << "\n[anti-crash] Arctium PrepareAntiCrash 机制\n";
  if (r.anticrash_patches)
    os << "  已写 " << r.anticrash_patches << " 条（完整性校验 ret 0 / remap 跳转错位）\n";
  else
    os << "  本次没有写入（该版本可能没有这些校验，或相关代码段尚未解密）\n";

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
  // 默认来源：<wowmod_dir>/mappings + <wowmod_dir>/files（Arctium 的磁盘形态）
  MappingLoadReport data = load_mappings(wowmod_dir);
  ModDataSet ds;
  ds.entries = data.entries;
  ds.files_dir = files_dir_for(wowmod_dir);
  ds.source_note = "mappings/files 目录";
  ModLoaderResult r = install_mod_loader_with_data(process, wowmod_dir, ds, wait_ms, kind);
  // 把 parse 统计补回去（自包含模式没有这些）
  r.entries_missing = data.missing_local;
  return r;
}

ModLoaderResult install_mod_loader_with_data(HANDLE process, const std::string& wowmod_dir,
                                             const ModDataSet& ds_in, uint32_t wait_ms,
                                             StubKind kind) {
  ModLoaderResult r;
  const ModDataSet& ds = ds_in;
  auto step = [&](const std::string& s) {
    r.steps.push_back(s);
    std::printf("  %s\n", s.c_str());
    std::fflush(stdout);
  };

  const int kNeedScore = 6;   // 满分 8；6 分 = 三个手指印里至少命中两个

  // ---- 1. 等客户端可扫（判据用【命中】，不靠任何间接指标）----
  //
  // 走过的弯路（都记在这，别再重复）：
  //   a) 明文页比例 >= 50%   -> 惰性解密下永远达不到
  //   b) Init 特征码必须出现 -> 用户实测 5 轮都是"未出现"，直接卡死，
  //      而且此时 5 个特征码里可能已经有能命中的了
  //   c) 分母只算读成功的页 -> 报出 142/142 的假象（其实是读到 142 页全零）
  //
  // 现在的判据只有一条：**目标特征码命中了吗**。
  // Init 只用来打印进度，不作为门槛 —— Arctium 用它是因为它对
  // 自己的客户端有效；对我们的客户端不成立就不该当阻塞条件。
  bool ready = false;
  size_t best_low = 0, last_checked = 0;
  const DWORD t0 = GetTickCount();
  int init_round = 0;
  for (;;) {
    const auto sig = scan_arctium_signatures(process, "", {"Init", "CustomFileIdHook"});
    bool init_found = false;
    uint64_t init_va = 0;
    int round_best = 0;
    uint64_t round_target = 0;
    size_t hits_n = 0;
    for (const auto& h : sig.hits) {
      if (h.name == "Init" && h.has_rx) {
        init_found = true;
        init_va = h.match_va;
      }
      if (h.name == "CustomFileIdHook") {
        ++hits_n;
        if (h.has_rx && h.semantic_score > round_best) {
          round_best = h.semantic_score;
          round_target = h.match_va;
        }
      }
    }
    const auto probe = dump_module_full(process, "", "");
    if (probe.text_checked) {
      best_low = probe.text_low_entropy;
      last_checked = probe.text_pages_total ? probe.text_pages_total : probe.text_checked;
    }
    std::printf("  第 %d 轮: 扫了 %zu 区域 / %.1f MB | 主映像 %.1f MB 读到 %.1f MB | "
                "Init %s | 明文页 %zu/%zu (不可读 %zu, 空白 %zu) | "
                "CustomFileIdHook %zu 处, 最佳 %d/8\n",
                init_round + 1, sig.images_scanned,
                static_cast<double>(sig.bytes_scanned) / (1024.0 * 1024.0),
                static_cast<double>(sig.main_image_size) / (1024.0 * 1024.0),
                static_cast<double>(sig.main_image_read) / (1024.0 * 1024.0),
                init_found ? "有" : "无", best_low, last_checked,
                probe.text_pages_unreadable, probe.text_pages_blank, hits_n, round_best);
    std::fflush(stdout);

    // 唯一门槛：目标特征码够分。Init 只做参考。
    if (round_target && round_best >= kNeedScore) {
      ready = true;
      break;
    }
    if (GetTickCount() - t0 > wait_ms) break;
    ::Sleep(2000);
    ++init_round;
  }
  if (!ready) {
    r.error = "等待期内 CustomFileIdHook 始终没有达到 " + std::to_string(kNeedScore) +
              "/8 的可执行命中（客户端未走到文件加载代码，或扫描范围未覆盖代码段）。"
              "请看上面每轮打印的【扫了多少 MB】—— 若明显小于客户端体积，就是范围问题。";
    return r;
  }
  step("客户端可扫（第 " + std::to_string(init_round + 1) + " 轮开始，明文 " +
       std::to_string(best_low) + "/" + std::to_string(last_checked) + " 页）");

  // ---- 2. 数据侧（已由调用方准备好）----
  if (ds.entries.empty()) {
    r.error = "没有可用的映射条目";
    return r;
  }
  r.entries_loaded = ds.entries.size();
  step("数据来源 " + ds.source_note + ", 可用 " + std::to_string(ds.entries.size()) + " 项" +
       (ds.files_dir.empty() ? "" : ("（files 目录 " + ds.files_dir + "）")));

  // ---- 3. 找 hook 点 ----
  //
  // 关键教训：这里【只扫一次】是错的。
  // 用户实测两次都停在「CustomFileIdHook 没找到可执行目标（语义分 0/8）」，
  // 而同一台机器稍早些时候能拿到 8/8 —— 中间只差"多等了一会儿"。
  // 原因是惰性解密：目标函数所在页只有在客户端真正执行到它之后才是明文，
  // 而客户端启动后要过一阵才走到 CAS 加载路径。
  //
  // 所以改成：边等边扫，最多等 wait_ms。一旦拿到可执行且语义分达标的
  // 命中就立刻停。这比"等够了再扫一次"可靠得多 —— 我们不知道确切时刻。
  uint64_t target = 0;
  int best = 0;
  bool best_rx = false;

  const DWORD scan_t0 = GetTickCount();
  int scan_round = 0;
  for (;;) {
    const auto sig = scan_arctium_signatures(process, "", {"Init", "CustomFileIdHook"});
    int round_best = 0;
    bool round_rx = false;
    uint64_t round_target = 0;
    size_t cands = 0, hits_n = 0;
    for (const auto& h : sig.hits) {
      if (h.name != "CustomFileIdHook") continue;
      ++hits_n;
      ++cands;
      if (h.has_rx) {
        const bool better = (h.semantic_score > round_best);
        if (better) {
          round_best = h.semantic_score;
          round_rx = true;
          round_target = h.match_va;
        }
      }
    }
    std::printf("  第 %d 轮: 扫了 %zu 个区域 / %.1f MB, CustomFileIdHook %zu 处命中, 最佳可执行 %d/8\n",
                scan_round + 1, sig.images_scanned,
                static_cast<double>(sig.bytes_scanned) / (1024.0 * 1024.0), hits_n, round_best);
    if (cands == 0) {
      std::printf("          （0 命中 ≠ 没解密 —— 而是这些区域里没有目标函数。"
                  "若下面 MB 数明显小于客户端体积，说明扫描范围没覆盖到代码段）\n");
    }
    std::fflush(stdout);

    if (round_target && round_best >= kNeedScore) {
      target = round_target;
      best = round_best;
      best_rx = true;
      break;
    }
    // 记住目前最好的（即使分不够），最后报错时能说清楚差多少
    if (round_target && round_best > best) {
      best = round_best;
      target = round_target;
      best_rx = true;
    }
    if (GetTickCount() - scan_t0 > wait_ms) break;
    ::Sleep(2000);
    ++scan_round;
  }
  if (!target || !best_rx) {
    r.error = "CustomFileIdHook 在等待期内始终没有可执行命中（最佳语义分 " +
              std::to_string(best) + "/8, 需要 >= " + std::to_string(kNeedScore) +
              "/8）。含义：本轮扫过的字节里不含这段代码 —— 要么扫描范围没覆盖到"
              "代码段（看上面每轮的 MB 数），要么目标函数所在页还没被解密。"
              "这不是需要你操作的事，是加载器自己的覆盖/时序问题。";
    return r;
  }
  if (best < kNeedScore) {
    r.error = "CustomFileIdHook 最佳只有 " + std::to_string(best) + "/8，低于所需 " +
              std::to_string(kNeedScore) + "/8。为避免 hook 错函数，已拒绝。";
    return r;
  }
  step("hook 目标 0x" + to_hex(target, 16) + "（语义分 " + std::to_string(best) + "/8, 第 " +
       std::to_string(scan_round + 1) + " 轮命中）");

  // ---- 3a. 【全进程挂起】----
  //
  // Arctium 的时序（src/Launcher.cs）：
  //     WaitForUnpack(...)            <- 等 Init 特征码
  //     PrepareAntiCrash()
  //         NtSuspendProcess(handle)  <- 全进程挂起
  //         ... 找并 queue 所有补丁 ...
  //     NtResumeProcess(handle)
  //     RemapAndPatch(...)            <- 写入
  //
  // 我们过去是边跑边写。客户端主线程随时可能执行到正在改的那几个字节，
  // 哪怕窗口只有几微秒，命中半条指令就是 EXCEPTION_INTERNAL_ERROR。
  // ThreadFreeze 只冻结我们枚举到的线程；NtSuspendProcess 由内核挂起
  // 整个进程，语义更彻底。这里照抄。
  //
  // 失败不致命：拿不到挂起权限时退化成"仍然写，但只在写的那一瞬间冻结线程"
  // （detour 内部本来就有 ThreadFreeze），并如实报告。
  bool suspended = false;
  {
    std::string serr;
    if (suspend_process(process, &serr)) {
      suspended = true;
      step("已全进程挂起（NtSuspendProcess），准备写入");
      // Arctium 的顺序（src/Launcher.cs LaunchGame）：
      //     NtSuspendProcess
      //     PrepareAntiCrash(...)   <- 只 queue，不写
      //     NowPatching: NoJump 也 queue
      //     NtResumeProcess
      //     RemapAndPatch(antiCrash) <- 真正写
      // 我们这里在挂起状态下直接写，效果等价（线程全停，没有撕裂窗口），
      // 而且不需要 materialize antiCrash 的 remap 逻辑。
      //
      // anti-crash 必须【最先】规划并写入：它要关掉的是客户端对代码页的
      // 完整性/remap 校验。晚一步写入，客户端可能在两次写入之间跑到校验，
      // 直接 EXCEPTION_INTERNAL_ERROR (0xC00000E5)。用户的崩溃就是这个。
    } else {
      step("警告: 全进程挂起失败（" + serr + "），将依赖写入瞬间的线程冻结");
    }
  }
  // 无论后面走哪条路径，函数返回前必须恢复进程。用守卫保证不漏。
  struct ResumeGuard {
    HANDLE p = nullptr;
    bool active = false;
    bool ok = false;
    ~ResumeGuard() {
      if (active && p) {
        std::string e;
        ok = resume_process(p, &e);
      }
    }
  } resume_guard{process, suspended, false};

  // ---- 3b. 先【规划】NoJump（只读，不写）----
  //
  // 用户实测踩过：跳板装成功、NoJump 失败，结果是「改了内存但行为没变」——
  // 比什么都不做更糟，因为占用了 id 表/字符串块并且 hook 了文件加载主函数。
  // 所以顺序改成：先把 NoJump 的规划做完（纯读），确认能打，再动第二半。
  // ---- 3a2. anti-crash（Arctium PrepareAntiCrash）----
  //
  // 缺了它，NoJump / 跳板即便装对了，客户端也会在几十秒内以
  // EXCEPTION_INTERNAL_ERROR 结束 —— 崩溃栈落在 ntdll!RtlReportCriticalFailure，
  // 因为那是"完整性校验失败"的统一出口，不是客户端代码的问题。
  {
    AntiCrashPlan ac = plan_anti_crash(process);
    if (!ac.ok) {
      step("anti-crash 规划失败: " + ac.error + "（继续，但客户端可能自行结束）");
    } else {
      step("anti-crash 规划: 完整性校验 " + std::to_string(ac.integrity_hits) +
           " 处, remap 校验 " + std::to_string(ac.remap_hits) + " 处, 跳转补丁 " +
           std::to_string(ac.remap_jump_patches) + " 条");
      if (!ac.patches.empty()) {
        if (apply_anti_crash(process, &ac)) {
          step("anti-crash 已写入 " + std::to_string(ac.patches.size()) + " 条");
          r.anticrash_patches = ac.patches.size();
        } else {
          step("anti-crash 写入不完整 —— 客户端可能被完整性校验结束");
        }
      }
      for (const auto& n : ac.notes) step("  " + n);
    }
  }

  std::map<std::string, uint32_t> by_rva;
  for (const auto& s2 : arctium_signature_specs()) {
    // 注意："s2.name != \"...\"" 是指针比较，两个字符串字面量在不同编译单元里
    // 是不同对象，所以永远不相等 —— 这段"按确证 RVA 点名"曾经【一次都没执行过】。
    // 必须用 std::string 比较。（编译器 -Wstring-compare 早就警告了。）
    const std::string sname = s2.name ? s2.name : "";
    if (sname != "LoadByFileIdAlternate" && sname != "LoadByFilePathAlternate") continue;
    if (s2.known_rva && s2.known_build == 68974) by_rva[sname] = s2.known_rva;
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
    //
    // 【这里曾经是错的】。Arctium（ModLoader.cs GetFileMappingData）写进
    // 字符串块的是 files 目录下的**磁盘绝对路径**：
    //     var pathBytes = Encoding.UTF8.GetBytes(f);   // f = 枚举出来的绝对路径
    //     loadedMappings.Add((BitConverter.GetBytes(id), pathBytes, stringLength));
    // 相对路径只用来在 mappings 里查 id，查完就丢。
    //
    // 我们过去存的是 game_path（"character/bloodelf/female/x.blp"），
    // 于是 stub 命中后返回给客户端的是一个相对路径指针，客户端拿去打开
    // 会相对它自己的当前目录（游戏根）解析 —— 那里没有这个文件。
    // 结果就是「两半都装上了、id 也命中、但一点都不生效」，而且与文件
    // 类型无关：.blp 贴图、.m2 模型、.skin 骨骼走的是同一条查表返回。
    // 这解释了为什么换模型/换贴图都没反应。
    const std::string files_dir_abs = ds.files_dir;
    std::vector<arctium::MappingEntry> entries;
    entries.reserve(ds.entries.size());
    for (const auto& e : ds.entries) {
      arctium::MappingEntry m;
      m.file_id = e.file_data_id;
      m.string_to_store = arctium::arctium_stored_path(files_dir_abs, e.game_path);
      entries.push_back(std::move(m));
    }
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
    // 【自检】字符串块里存的必须是可打开的绝对路径。
    // 这不是"顺便打印一下"：只要这里不是绝对路径，模组就一定不生效，
    // 而现场表现（跳板装好、客户端不崩、画面不变）极难反推回来。
    {
      size_t abs_count = 0, sample_n = 0;
      std::string sample;
      for (const auto& m : entries) {
        const bool is_abs = (m.string_to_store.size() >= 3 &&
                             std::isalpha(static_cast<unsigned char>(m.string_to_store[0])) &&
                             m.string_to_store[1] == ':' && m.string_to_store[2] == '/');
        if (is_abs) ++abs_count;
        if (sample_n < 1 && !m.string_to_store.empty()) {
          sample = m.string_to_store;
          ++sample_n;
        }
      }
      step("字符串块自检: " + std::to_string(abs_count) + "/" + std::to_string(entries.size()) +
           " 条是绝对路径" + (abs_count == entries.size() ? "" : "  <-- 有问题"));
      if (!sample.empty()) step("  示例: " + sample);
      // 相对路径 = 客户端按自己的当前目录解析 = 找不到文件 = 什么都不生效。
      if (abs_count != entries.size()) {
        r.error = "字符串块里有 " + std::to_string(entries.size() - abs_count) +
                  " 条不是绝对路径。Arctium 存的是 files 下的磁盘绝对路径，"
                  "存相对路径客户端打不开对应文件，装了也不会生效 —— 已停止，不写入 hook。";
        return r;
      }
    }

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
    // 同样的问题：返回给客户端的必须是能直接打开的磁盘绝对路径。
    req.entries.reserve(ds.entries.size());
    {
      const std::string fda = ds.files_dir;
      for (const auto& e : ds.entries)
        req.entries.emplace_back(e.file_data_id, arctium::arctium_stored_path(fda, e.game_path));
    }

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

  // 显式恢复进程（守卫还会兜一次，但这里要能把失败报出来）
  if (suspended) {
    std::string rerr;
    if (resume_process(process, &rerr)) {
      step("已恢复进程（NtResumeProcess），客户端可以继续运行");
      resume_guard.active = false;   // 交给守卫不要再恢复一次
    } else {
      r.error = "补丁已写入，但恢复进程失败: " + rerr + "（请手动结束客户端后重试）";
      return r;
    }
  }

  r.ok = true;
  return r;
}

}  // namespace win
}  // namespace wowmod
#endif
