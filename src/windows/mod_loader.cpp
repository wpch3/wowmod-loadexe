// 模组加载器实现。见 mod_loader.hpp 的说明。
// SPDX-License-Identifier: MIT
#ifdef _WIN32

#include "windows/mod_loader.hpp"

#include "wowmod/log.hpp"
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
  os << "[第一半] NoJump 分支补丁: ";
  if (r.branch_patched)
    os << "已打 " << r.branch_count << " 条（je rel32 -> 00 00 00 00）\n";
  else
    os << "未完成\n";

  os << "[第二半] FileDataID -> 本地路径 查表跳板: ";
  if (r.hook_installed) {
    char b[256];
    std::snprintf(b, sizeof(b), "已安装于 0x%llX\n",
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
    os << "未安装\n";
  }

  os << "[anti-crash] PrepareAntiCrash 机制: ";
  if (r.anticrash_patches)
    os << "已写 " << r.anticrash_patches << " 条（完整性校验 ret 0 / remap 跳转错位）\n";
  else
    os << "本次没有写入（该版本可能没有这些校验，或相关代码段尚未解密）\n";

  os << "[数据] 可用 " << r.entries_loaded << " 项，磁盘缺失 " << r.entries_missing << " 项\n";

  if (!r.steps.empty()) {
    os << "步骤:\n";
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
                                             StubKind kind, const ModLoaderOptions& opts) {
  ModLoaderResult r;
  const ModDataSet& ds = ds_in;
  auto step = [&](const std::string& s) {
    r.steps.push_back(s);
    wowmod::logf("  %s", s.c_str());
  };

  // ---- 1. 等客户端可扫（判据用【命中】，不靠任何间接指标）----
  //
  // 走过的弯路（都记在这，别再重复）：
  //   a) 明文页比例 >= 50%   -> 惰性解密下永远达不到
  //   b) Init 特征码必须出现 -> 用户实测 5 轮都是"未出现"，直接卡死，
  //      而且此时 5 个特征码里可能已经有能命中的了
  //   c) 分母只算读成功的页 -> 报出 142/142 的假象（其实是读到 142 页全零）
  //
  // 【曾经最严重的一个错误，必须写在这】
  //
  // 我发明了「CustomFileIdHook 语义分 >= 6/8 才算就绪」这个门槛。
  // Arctium 里根本没有这个东西。结果就是你实测的那份日志：
  //     第 1 轮 ... Init 有 ... CustomFileIdHook 0 处
  //     第 2~5 轮 ... Init 无 ... CustomFileIdHook 1 处, 最佳 0/8
  //     [失败] 等待期内 CustomFileIdHook 始终没有达到 6/8 ...
  // 第 1 轮 Init 明明 `有` —— 客户端**已经初始化完成**，正是 Arctium
  // 认为可以打补丁的时刻，我们却把它拒了，然后白白等到超时。
  //
  // Arctium 的判据（src/Launcher.cs WaitForUnpack）只有两条：
  //   1) Init 特征码出现
  //   2) 该特征码里那条 mov 的立即数指向的地址，其字节变为非 0
  // 满足即 PrepareAntiCrash -> 排队 NoJump -> HookClient，从不看任何分数。
  //
  // 所以这里改成：
  //   * Init 出现  => 立刻结束等待（这才是正确时机）
  //   * 不出现      => 等满 wait_ms（老客户端/其它版本兜底）
  //   * 语义分 / 明文页只打印，作为诊断信息，绝不作为门槛
  bool ready = false;
  // 这两个循环都会用到「上次看到的映像信息」，报错时必须能说出真实数值，
  // 所以声明在函数作用域而不是循环里。
  uint64_t last_image_base = 0;
  size_t last_image_size = 0, last_image_read = 0;
  bool init_found = false;
  uint64_t init_va = 0;
  size_t best_low = 0, last_checked = 0;
  int hook_hits = 0, hook_best = 0;
  const DWORD t0 = GetTickCount();
  int init_round = 0;
  for (;;) {
    const auto sig = scan_arctium_signatures(process, "", {"Init", "CustomFileIdHook"});
    bool round_init = false;
    int round_best = 0;
    size_t hits_n = 0;
    for (const auto& h : sig.hits) {
      if (h.name == "Init" && h.has_rx) {
        round_init = true;
        if (!init_va) init_va = h.match_va;
      }
      if (h.name == "CustomFileIdHook") {
        ++hits_n;
        if (h.has_rx && h.semantic_score > round_best) round_best = h.semantic_score;
      }
    }
    if (round_init) init_found = true;
    if (round_best > hook_best) hook_best = round_best;
    hook_hits = static_cast<int>(hits_n);
    // 只在第 0 轮采样解密进度（整块读很贵，轮询会拖垮客户端）
    const auto probe = (init_round == 0) ? dump_module_full(process, "", "") : ModuleDump{};
    if (probe.text_checked) {
      best_low = probe.text_low_entropy;
      last_checked = probe.text_pages_total ? probe.text_pages_total : probe.text_checked;
    }
    wowmod::logf("  第 %d 轮: 扫了 %zu 区域 / %.1f MB | 主映像 %.1f MB 读到 %.1f MB | "
                 "Init %s | 明文页 %zu/%zu | CustomFileIdHook %zu 处 (最佳 %d/8)\n",
                 init_round + 1, sig.images_scanned,
                 static_cast<double>(sig.bytes_scanned) / (1024.0 * 1024.0),
                 static_cast<double>(sig.main_image_size) / (1024.0 * 1024.0),
                 static_cast<double>(sig.main_image_read) / (1024.0 * 1024.0),
                 init_found ? "有" : "无", best_low, last_checked, hits_n, round_best);

    // Arctium 的通过条件。
    if (init_found) {
      ready = true;
      break;
    }
    // 客户端是不是还活着？必须查。
    //
    // 用户实测：第 1 轮 Init 有，第 2~5 轮 Init 全无。一个已经初始化
    // 完成的进程，同一条特征码不可能"消失" —— 除非进程本身没了，
    // 或者壳把页面重新加密/换掉了。不检查的话，我们会一直等到超时，
    // 然后报一个"特征码没出现"的假原因，把排查方向彻底带偏。
    {
      DWORD code = 0;
      if (GetExitCodeProcess(process, &code) && code != STILL_ACTIVE) {
        r.error = "客户端在等待期间退出了（exit code 0x" + to_hex(code, 8) +
                  "，第 " + std::to_string(init_round + 1) + " 轮）。"
                  "这不是特征码问题 —— 客户端自己先结束了。"
                  "请确认它能独立启动到角色选择界面（不加载任何模组时也必须能），"
                  "再试。";
        return r;
      }
    }
    if (GetTickCount() - t0 > wait_ms) break;
    ::Sleep(1000);
    ++init_round;
  }
  if (!ready) {
    // 不是「找不到特征码就失败」—— 而是 Init 在等待期内确实没出现。
    // 这仍然可以继续（有些版本/完整包里这条特征码形态不同），
    // 但必须如实说明，让后面的判定自己决定。
    step("警告: 等待期内 Init 特征码未出现（" + std::to_string(init_round + 1) +
         " 轮，明文 " + std::to_string(best_low) + "/" + std::to_string(last_checked) +
         " 页）。继续尝试定位，不中止。");
  } else {
    step("客户端已初始化（Init 出现，第 " + std::to_string(init_round + 1) +
         " 轮；CustomFileIdHook 命中 " + std::to_string(hook_hits) + " 处，最佳语义分 " +
         std::to_string(hook_best) + "/8）");
  }

  // ---- 2. 数据侧（已由调用方准备好）----
  //
  // 【必须在任何提前返回之前记下条目数】
  //
  // 以前这里在函数末尾才赋值，而第 3 节的等待循环可能先失败返回，
  // 于是报告里打出「[数据] 可用 0 项」—— 用户明明扫到了 796 项，
  // 却看到 0，会以为数据丢了、白扫了一遍。这是纯粹的误导。
  if (ds.entries.empty()) {
    r.entries_loaded = 0;
    r.error = "没有可用的映射条目";
    return r;
  }
  r.entries_loaded = ds.entries.size();
  step("数据来源 " + ds.source_note + ", 可用 " + std::to_string(ds.entries.size()) + " 项" +
       (ds.files_dir.empty() ? "" : ("（files 目录 " + ds.files_dir + "）")));

  // ---- 3. 找 hook 点 ----
  //
  // 【这一节以前是错的，错得很彻底，记录在此避免再犯】
  //
  // 我发明了一个「语义分 >= 6/8 才算找到」的门槛，并且把「扫到了
  // CustomFileIdHook 但分数不够」当成失败。结果就是你看到的那份日志：
  //     第 2~5 轮: CustomFileIdHook 1 处, 最佳 0/8     -> 判定失败
  // 而**第 1 轮明明写着 `Init 有`** —— 也就是客户端已经初始化完成，
  // 正是 Arctium 认为「可以开始打补丁了」的时刻。我们却因为这个
  // 自己发明的分数把它拒了。
  //
  // Arctium 的判据（src/Launcher.cs WaitForUnpack）只有两条：
  //   1) Init 特征码出现
  //   2) initOffset += *(int*)(match+2) + 10;  该处字节变非 0
  // 满足就 PrepareAntiCrash()，然后直接 QueuePatch 打 LoadByFileId /
  // LoadByFilePath，再 HookClient 找 CustomFileIdHook。
  // 它**从不检查**任何「语义分」，也不等什么「解密进度」。
  //
  // 至于「模组什么时候加载」——客户端一进角色选择界面就已经在按
  // FileDataID 取资源了，所以补丁必须在那之前就位。等得越久越糟。
  //
  // 现在的策略：
  //   * 每轮扫 Init + CustomFileIdHook
  //   * Init 出现 => 立即停止等待（等同 Arctium）
  //   * 同时记录 CustomFileIdHook 的命中：有**可执行**命中就直接用；
  //     只有不可执行的命中，也先用它（写入时会让目标页可写可执行），
  //     并在报告里如实写明「该页原本不可执行」
  //   * 语义分只作为诊断打印，**不再是门槛**
  uint64_t target = 0;
  int best = 0;
  bool best_rx = false;
  bool init_seen = false;
  std::string pick_note;

  const DWORD scan_t0 = GetTickCount();
  int scan_round = 0;
  for (;;) {
    const auto sig = scan_arctium_signatures(process, "", {"Init", "CustomFileIdHook"});
    last_image_base = sig.main_image_base;
    last_image_size = sig.main_image_size;
    last_image_read = sig.main_image_read;
    int round_best = 0;
    uint64_t round_target = 0;
    bool round_rx = false;
    bool round_any = false;
    uint64_t round_any_va = 0;
    size_t hits_n = 0;
    for (const auto& h : sig.hits) {
      if (h.name == "Init" && h.has_rx) init_seen = true;
      if (h.name != "CustomFileIdHook") continue;
      ++hits_n;
      round_any = true;
      if (!round_any_va) round_any_va = h.match_va;
      if (h.has_rx && (!round_rx || h.semantic_score > round_best)) {
        round_best = h.semantic_score;
        round_rx = true;
        round_target = h.match_va;
      }
    }
    wowmod::logf("  第 %d 轮: 扫了 %zu 个区域 / %.1f MB | 主映像 %.1f MB 读到 %.1f MB | "
                 "Init %s | CustomFileIdHook %zu 处 (可执行 %s, 语义分 %d/8)\n",
                 scan_round + 1, sig.images_scanned,
                 static_cast<double>(sig.bytes_scanned) / (1024.0 * 1024.0),
                 static_cast<double>(sig.main_image_size) / (1024.0 * 1024.0),
                 static_cast<double>(sig.main_image_read) / (1024.0 * 1024.0),
                 init_seen ? "有" : "无", hits_n, round_rx ? "是" : "否", round_best);

    // 记录下来（不论可执行与否），供 Init 提前结束时兜底
    if (round_target) {
      if (!best_rx || round_best > best) { best = round_best; target = round_target; best_rx = true; }
    } else if (round_any && !target) {
      // 只有不可执行命中：先记下，等 Init 出现时就用它
      best = round_best;
      target = round_any_va;
    }

    // 注意：走到这里时第一个循环【已经】确认过 Init（否则我们不会在
    // 这里）。所以这里【不能】再拿 Init 当退出条件 —— 那会让这个循环
    // 在第一次迭代就 break，等于"只扫一次"。
    // 这个循环要等的是：目标特征码出现（任何一处命中）。
    if (target) break;
    if (GetTickCount() - scan_t0 > wait_ms) break;
    ::Sleep(1000);
    ++scan_round;
  }

  // 到这里唯一还需要的条件：**真的找到了一处命中**。
  //
  // 不再要求语义分、也不再要求那页「原本可执行」：
  //   * 语义分是我自己发明的门槛，Arctium 从不看它
  //   * 命中页原本是否可执行，取决于当时是否已解密/是否被壳映射成
  //     PAGE_READWRITE —— 壳在初始化阶段确实会这样映射。
  //     写入时我们本来就会用 VirtualProtectEx 把那页改成可写可执行，
  //     所以「原本不可执行」不该导致放弃。
  //
  // 真正需要拒绝的情况只有一种：**一处都找不到**（或者找到的位置
  // 明显不对，比如落在 PE 头里）。那种情况下拒绝是对的。
  if (!target) {
    r.error = "等待期内一处 CustomFileIdHook 都没找到。映像 0x" + to_hex(last_image_base, 16) +
              "，SizeOfImage " + std::to_string(last_image_size / 1048576) +
              " MB，实际读到 " + std::to_string(last_image_read / 1048576) + " MB。"
              "若「实际读到」明显小于 SizeOfImage，是读取覆盖问题；"
              "若两者接近仍 0 命中，说明这个客户端的文件加载函数和 Arctium 的特征码"
              "不一致（版本差异），需要换特征码，而不是重试。";
    return r;
  }
  step("hook 目标 0x" + to_hex(target, 16) + "（第 " + std::to_string(scan_round + 1) +
       " 轮命中；语义分 " + std::to_string(best) + "/8，" +
       (best_rx ? "命中页可执行" : "命中页原本不可执行，写入时会改成可写可执行") + "）");

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
    AntiCrashPlan ac = plan_anti_crash(process, opts.cert_patches);
    if (!ac.ok) {
      step("anti-crash 规划失败: " + ac.error + "（继续，但客户端可能自行结束）");
    } else {
      step("anti-crash 规划: 完整性校验 " + std::to_string(ac.integrity_hits) +
           " 处, remap 校验 " + std::to_string(ac.remap_hits) + " 处, 跳转补丁 " +
           std::to_string(ac.remap_jump_patches) + " 条" +
           (opts.cert_patches ? (", 证书补丁 " + std::to_string(ac.cert_patches) + " 条") : ""));
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
    // 【NoJump 必须重试，不能一次失败就放弃】
    //
    // 线上实测：CustomFileIdHook 在 RVA 0x33E06A0 能稳定命中，
    // 但 LoadByFileId/Path 的 RVA（0x33D7976 / 0x33D7B58）在同一个
    // .text 段里却 0 命中，同时明文页只有 22/260 (8.5%)。
    //
    // 说明壳是【按需解密】：只有客户端真正执行到的页才是明文。
    // 那两处是 CASC 加载分支，客户端要到「开始读资源/进登录界面」
    // 才会执行到。Arctium 的 WaitForUnpack 一直在重读整幅映像，
    // 直到 Init 那条特征码出现 —— 它天然覆盖了这个等待。
    //
    // 所以这里对 NoJump 也做等待重试，而不是一次不中就直接失败。
    const DWORD br_t0 = GetTickCount();
    for (int attempt = 0;; ++attempt) {
      branch_plan = plan_branch_patches(process, by_rva);
      if (branch_plan.ok) {
        if (attempt > 0) step("NoJump 第 " + std::to_string(attempt + 1) + " 次重试后定位成功");
        break;
      }
      // 客户端是不是已经没了？没了就别等了。
      DWORD code = 0;
      if (GetExitCodeProcess(process, &code) && code != STILL_ACTIVE) {
        r.error = "客户端在等待 NoJump 目标期间退出（exit=0x" + to_hex(code, 8) + "）";
        return r;
      }
      if (GetTickCount() - br_t0 > wait_ms) {
        step("NoJump 重试 " + std::to_string(attempt + 1) + " 次仍未定位（已等 " +
             std::to_string((GetTickCount() - br_t0) / 1000) + " 秒）");
        break;
      }
      step("NoJump 第 " + std::to_string(attempt + 1) +
           " 次未定位到目标（代码页可能还没解密），1 秒后重试…");
      ::Sleep(1000);
    }
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
    //
    // 【必须用条目自己的 local_path】
    //
    // 自包含模式（--mods）下，文件散落在用户自己的模组目录里，
    // 只有一个"游戏相对路径"，磁盘位置和 game_path 完全不对应。
    // 如果这里用 files_dir + game_path 去拼，拼出来的路径根本不存在，
    // 客户端打开失败 —— 又是"装好了但不生效"。
    // load_mappings 那边已经把 local_path 算成 files\<game_path>，
    // 所以两种来源都只需原样取 e.local_path。
    std::vector<arctium::MappingEntry> entries;
    entries.reserve(ds.entries.size());
    for (const auto& e : ds.entries) {
      arctium::MappingEntry m;
      m.file_id = e.file_data_id;
      // 兜底：local_path 为空时才退回 files_dir + game_path（老数据形态）
      m.string_to_store = e.local_path.empty()
                              ? arctium::arctium_stored_path(ds.files_dir, e.game_path)
                              : e.local_path;
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
      // 还要确认这些路径在磁盘上【真的存在】。绝对路径但文件不存在，
      // 客户端依然打不开 —— 那和存相对路径的结果一模一样。
      size_t exist_count = 0;
      for (const auto& m : entries) {
        std::error_code fec;
        if (!m.string_to_store.empty() &&
            std::filesystem::is_regular_file(std::filesystem::u8path(m.string_to_store), fec))
          ++exist_count;
      }
      step("字符串块自检: " + std::to_string(abs_count) + "/" + std::to_string(entries.size()) +
           " 条是绝对路径, " + std::to_string(exist_count) + " 条磁盘上存在" +
           ((abs_count == entries.size() && exist_count == entries.size()) ? ""
                                                                          : "  <-- 有问题"));
      if (!sample.empty()) step("  示例: " + sample);
      // 相对路径 = 客户端按自己的当前目录解析 = 找不到文件 = 什么都不生效。
      if (exist_count != entries.size()) {
        r.error = "字符串块里有 " + std::to_string(entries.size() - exist_count) +
                  " 条路径在磁盘上不存在（客户端打开会失败，装了也不生效）—— 已停止，不写入 hook。";
        return r;
      }
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
    for (const auto& e : ds.entries)
      req.entries.emplace_back(e.file_data_id, e.local_path.empty()
                                                   ? arctium::arctium_stored_path(ds.files_dir,
                                                                                 e.game_path)
                                                   : e.local_path);

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
