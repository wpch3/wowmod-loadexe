// 崩溃现场检查器实现（只读）。
// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/crash_evidence.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

// ---- 极简 minidump 解析 ----
//
// 只走流目录找 EXCEPTION_STREAM(6)，不依赖 dbghelp.dll。
// 布局（64 位）：
//   MINIDUMP_HEADER: sig(4) ver(4) num_streams(4) dir_rva(4) ...
//   MINIDUMP_DIRECTORY 每项 12 字节: stream_type(4) data_size(4) rva(4)
//   MINIDUMP_EXCEPTION_STREAM:
//     thread_id(4) __align(4)
//     EXCEPTION_RECORD: code(4) flags(4) record_ptr(8) address(8) num_params(4) __align(4)
//                       info[0](8) info[1](8) ...
constexpr uint32_t kSig = 0x504D444Du;  // 'MDMP'
constexpr uint32_t kExceptionStream = 6;

uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t rd64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
  return v;
}

}  // namespace

bool parse_minidump_exception(const std::string& path, CrashEvidence* out, std::string* err) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, utf8_to_wide(path).c_str(), L"rb") != 0 || !f) {
    if (err) *err = "打不开转储文件";
    return false;
  }
  uint8_t hdr[32];
  if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr) || rd32(hdr) != kSig) {
    fclose(f);
    if (err) *err = "不是 minidump 文件";
    return false;
  }
  const uint32_t nstreams = rd32(hdr + 8);
  const uint32_t dir_rva = rd32(hdr + 12);
  if (nstreams == 0 || nstreams > 4096) {
    fclose(f);
    if (err) *err = "流数量异常";
    return false;
  }
  std::vector<uint8_t> dir(static_cast<size_t>(nstreams) * 12);
  if (fseek(f, static_cast<long>(dir_rva), SEEK_SET) != 0 ||
      fread(dir.data(), 1, dir.size(), f) != dir.size()) {
    fclose(f);
    if (err) *err = "读流目录失败";
    return false;
  }
  for (uint32_t i = 0; i < nstreams; ++i) {
    const uint8_t* d = dir.data() + i * 12;
    if (rd32(d) != kExceptionStream) continue;
    const uint32_t rva = rd32(d + 8);
    uint8_t buf[168];
    if (fseek(f, static_cast<long>(rva), SEEK_SET) != 0 ||
        fread(buf, 1, sizeof(buf), f) != sizeof(buf)) {
      fclose(f);
      if (err) *err = "读 EXCEPTION_STREAM 失败";
      return false;
    }
    out->found = true;
    out->thread_id = rd32(buf);              // thread_id
    out->exception_code = rd32(buf + 8);     // ExceptionRecord.ExceptionCode
    out->rip = rd64(buf + 24);               // ExceptionRecord.ExceptionAddress
    out->faulting_address = rd64(buf + 40);// ExceptionInformation[1]
    out->source = path;
    fclose(f);
    return true;
  }
  fclose(f);
  if (err) *err = "转储里没有 EXCEPTION_STREAM";
  return false;
}

CrashEvidence find_latest_illegal_instruction_crash(const std::string& game_dir) {
  CrashEvidence best;
  namespace fs = std::filesystem;

  std::vector<fs::path> roots;
  auto push_env = [&](const char* name) {
    const char* v = std::getenv(name);
    if (!v) return;
    roots.emplace_back(fs::u8path(v));
  };
  push_env("LOCALAPPDATA");
  if (!roots.empty()) {
    roots.push_back(roots.front() / "CrashDumps");
    roots.push_back(roots.front() / "Microsoft" / "Windows" / "WER" / "ReportArchive");
    roots.push_back(roots.front() / "Microsoft" / "Windows" / "WER" / "ReportQueue");
  }
  if (!game_dir.empty()) {
    roots.emplace_back(fs::u8path(game_dir) / "Errors");
    roots.emplace_back(fs::u8path(game_dir) / "Logs");
  }

  fs::file_time_type newest{};
  bool have_newest = false;
  for (const auto& root : roots) {
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) continue;
    // 只扫两层，够覆盖 CrashDumps 与 WER\ReportArchive\<报告名>\ 的布局
    for (auto it = fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
      if (ec) break;
      if (it.depth() >= 2) { it.disable_recursion_pending(); }
      std::error_code e2;
      if (!it->is_regular_file(e2) || e2) continue;
      const auto name = it->path().filename().u8string();
      std::string lower = name;
      for (auto& c : lower) c = static_cast<char>(::tolower(c));
      // WER 的报告名里带异常码；转储文件通常叫 *.dmp
      const bool maybe_dump = lower.size() > 4 && lower.substr(lower.size() - 4) == ".dmp";
      const bool wer_report = lower.find("c00000e5") != std::string::npos ||
                              lower.find("illegal_instruction") != std::string::npos;
      if (!maybe_dump && !wer_report) continue;
      auto t = fs::last_write_time(it->path(), e2);
      if (e2) continue;
      if (!have_newest || t > newest) {
        newest = t;
        have_newest = true;
        best.note = "候选: " + it->path().u8string();
      }
      if (maybe_dump) {
        CrashEvidence one;
        std::string perr;
        if (parse_minidump_exception(it->path().u8string(), &one, &perr) && one.found) {
          if (!best.found || t > newest) {
            best = one;
            newest = t;
          }
        }
      }
    }
  }
  return best;
}

int classify_crash_address(const CrashEvidence& ev,
                           const std::vector<std::pair<uint64_t, uint64_t>>& hooked_ranges,
                           const std::vector<std::pair<uint64_t, uint64_t>>& stub_ranges) {
  if (!ev.found || !ev.rip) return 0;
  for (const auto& r : hooked_ranges) {
    if (ev.rip >= r.first && ev.rip < r.second) return 1;
  }
  for (const auto& r : stub_ranges) {
    if (ev.rip >= r.first && ev.rip < r.second) return 2;
  }
  return 0;
}

std::string describe_crash_verdict(const CrashEvidence& ev, int verdict) {
  char buf[512];
  if (!ev.found) {
    std::snprintf(buf, sizeof(buf),
                  "  没有找到崩溃转储的可解析记录，无法判定崩溃点是否与探针相关。\n"
                  "  （WER 的转储不一定开启；可以在「系统属性 -> 高级 -> 启动和故障恢复」里打开\n"
                  "    「写入调试信息」，之后崩溃就会留下可解析的 .dmp）\n");
    return buf;
  }
  std::string s;
  std::snprintf(buf, sizeof(buf),
                "  崩溃码 0x%08X   RIP 0x%llx   线程 %u\n  来源: %s\n",
                ev.exception_code, static_cast<unsigned long long>(ev.rip), ev.thread_id,
                ev.source.c_str());
  s += buf;
  switch (verdict) {
    case 1:
      s += "  [判定] 崩溃地址【落在我们改写的跳转区间内】—— 探针写入有问题（多半是原子性）。\n";
      break;
    case 2:
      s += "  [判定] 崩溃地址【落在我们自己的跳板/trampoline 里】—— 跳板机器码有 bug。\n";
      break;
    default:
      s += "  [判定] 崩溃地址【不在】我们改过的任何字节里 —— 与探针无直接关系，\n"
           "         请不要再去改 hook 代码，问题在别处。\n";
      break;
  }
  return s;
}

}  // namespace win
}  // namespace wowmod
#endif
