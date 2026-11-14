// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/mem_scan.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "wowmod/discover.hpp"
#include "wowmod/json.hpp"
#include "wowmod/util.hpp"
#include "wowmod/version.hpp"
#include "windows/fileid_hook.hpp"
#include "windows/runtime.hpp"

namespace wowmod {
namespace win {

namespace {

uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// 可读且已提交的保护属性（排除 PAGE_NOACCESS / PAGE_GUARD）
bool readable(DWORD protect) {
  if (protect & PAGE_GUARD) return false;
  DWORD base = protect & 0xFF;
  return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_EXECUTE_READ ||
         base == PAGE_EXECUTE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_WRITECOPY;
}

std::wstring wide(const std::string& s) { return utf8_to_wide(s); }

}  // namespace

bool dump_module_image(const std::string& module, const std::string& out_path,
                       std::vector<uint8_t>* image, std::string* err) {
  if (err) err->clear();
  HMODULE base = module.empty() ? GetModuleHandleW(nullptr) : GetModuleHandleW(wide(module).c_str());
  if (!base) { if (err) *err = "模块未加载: " + (module.empty() ? std::string("主 exe") : module); return false; }

  const uint8_t* p = reinterpret_cast<const uint8_t*>(base);
  // 从 PE 头读 SizeOfImage（内存映像里 PE 头就在基址）
  if (IsBadReadPtr(p, 0x1000)) { if (err) *err = "PE 头不可读"; return false; }
  if (p[0] != 'M' || p[1] != 'Z') { if (err) *err = "模块基址不是 MZ"; return false; }
  uint32_t pe_off = rd32(p + 0x3C);
  if (pe_off > 0x1000 || rd32(p + pe_off) != 0x00004550u) { if (err) *err = "PE 头无效"; return false; }
  uint16_t magic = static_cast<uint16_t>(p[pe_off + 24] | (p[pe_off + 25] << 8));
  size_t opt = pe_off + 24;
  uint32_t size_of_image = rd32(p + opt + (magic == 0x10B ? 52 : 56));  // PE32 字段少 4 字节
  if (size_of_image == 0 || size_of_image > 512u * 1024u * 1024u) { if (err) *err = "SizeOfImage 异常"; return false; }

  std::vector<uint8_t> buf(size_of_image, 0);
  size_t copied = 0;
  for (uint8_t* q = const_cast<uint8_t*>(p); q < p + size_of_image;) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(q, &mbi, sizeof(mbi))) break;
    uint8_t* region = static_cast<uint8_t*>(mbi.BaseAddress);
    size_t region_size = mbi.RegionSize;
    if (region + region_size > p + size_of_image) region_size = static_cast<size_t>(p + size_of_image - region);
    if (region_size == 0) break;
    if (mbi.State == MEM_COMMIT && readable(mbi.Protect)) {
      size_t off = static_cast<size_t>(region - p);
      SIZE_T got = 0;
      if (ReadProcessMemory(GetCurrentProcess(), region, buf.data() + off, region_size, &got)) copied += got;
      else {
        // 逐页读，跳过中间不可读的页
        for (size_t o = 0; o < region_size; o += 0x1000) {
          SIZE_T g = 0;
          size_t n = std::min<size_t>(0x1000, region_size - o);
          if (ReadProcessMemory(GetCurrentProcess(), region + o, buf.data() + off + o, n, &g)) copied += g;
        }
      }
    }
    q = region + region_size;
  }
  if (image) *image = buf;
  if (!out_path.empty()) {
    std::string werr;
    if (!write_text_file(out_path, std::string(buf.begin(), buf.end()), &werr)) {
      if (err) *err = werr;
      return false;
    }
  }
  if (err) *err = "已转储 " + std::to_string(buf.size()) + " 字节，其中可读 " + std::to_string(copied) + " 字节";
  return true;
}

void start_runtime_scan() {
  Runtime& rt = runtime();
  if (!rt.ready || !rt.cfg.hooks.runtime_scan) return;
  // 诊断脚本会在自身进程里 LoadLibraryW + FreeLibrary 探测本 DLL；
  // 那时不能留下引用已卸载模块的后台线程。
  auto env_set = [](const wchar_t* n) { return GetEnvironmentVariableW(n, nullptr, 0) != 0; };
  if (env_set(L"WOWMOD_PROBE") || env_set(L"WOWMOD_RUNTIME_SCAN_OFF")) return;
  // 已经在磁盘上找到唯一 hook 点时，不需要运行时扫描
  if (rt.hooks.mode == "fileid") return;

  std::thread([]() {
    Runtime& r = runtime();
    int delay = std::max(0, std::min(60000, r.cfg.hooks.runtime_delay_ms));
    Sleep(static_cast<DWORD>(delay));

    std::vector<std::string> modules;
    modules.push_back("");  // 主 exe
    for (const auto& m : r.cfg.hooks.runtime_modules) modules.push_back(m);
    if (r.cfg.hooks.runtime_modules.empty()) {
      for (const auto& d : r.ci.companion_dlls) modules.push_back(d);
      for (const auto& d : r.cfg.hooks.scan_targets) modules.push_back(d);
    }
    std::sort(modules.begin(), modules.end());
    modules.erase(std::unique(modules.begin(), modules.end()), modules.end());

    std::string dump_dir = r.cfg.hooks.runtime_dump;
    if (!dump_dir.empty()) {
      while (!dump_dir.empty() && (dump_dir.back() == '/' || dump_dir.back() == '\\')) dump_dir.pop_back();
    }
    Json modules_json = Json::make_array();
    size_t total_candidates = 0;
    for (const auto& mod : modules) {
      std::string label = mod.empty() ? "main.exe" : mod;
      std::string out;
      if (!dump_dir.empty()) out = dump_dir + "/" + label + ".img";
      std::vector<uint8_t> image;
      std::string derr;
      if (!dump_module_image(mod, out, &image, &derr)) {
        dlog("runtime scan: 跳过 " + label + ": " + derr);
        continue;
      }
      dlog("runtime scan: " + label + " " + derr);
      PeImage pe;
      std::string perr;
      bool is_pe = pe.load(image, &perr, true);
      DiscoveryReport rep = discover_hook_points(image, default_anchors(), true);
      rep.exe = label;

      Json m = Json::make_object();
      m.set("module", Json::make_string(label));
      m.set("imageSize", Json::make_number(static_cast<double>(image.size())));
      m.set("pe", Json::make_bool(is_pe));
      m.set("anchorsFound", Json::make_array());
      Json af = Json::make_array();
      for (const auto& a : rep.anchors_found) af.push(Json::make_string(a));
      m.set("anchorsFound", af);
      m.set("xrefCount", Json::make_number(static_cast<double>(rep.xref_count)));
      m.set("candidates", Json::make_number(static_cast<double>(rep.candidates.size())));
      Json cands = Json::make_array();
      for (const auto& c : rep.candidates) cands.push(c.to_json());
      m.set("candidatePatterns", cands);
      modules_json.push(m);
      total_candidates += rep.candidates.size();

      // 默认只产出候选，不自动对未验证的特征下断点。
      if (r.cfg.hooks.runtime_auto_install && !rep.candidates.empty() && rep.candidates.front().unique_matches == 1) {
        const auto& c = rep.candidates.front();
        std::string herr;
        if (!install_runtime_fileid_hook(mod, c.code_rva, c.pattern, "rdx", &herr))
          dlog("runtime scan: 自动安装失败: " + herr);
        else
          dlog("runtime scan: 自动安装 hook @ " + label + " rva " + to_hex(c.code_rva, 8) + ": " + herr);
      }
      if (!dump_dir.empty())
        write_text_file(dump_dir + "/" + label + ".candidates.json", rep.to_json().dump(2), nullptr);
    }
    std::string report_path = dump_dir.empty() ? r.cfg.log.file + ".runtime.json" : dump_dir + "/runtime-report.json";
    Json rep = Json::make_object();
    rep.set("mode", Json::make_string("runtime-memory-scan"));
    rep.set("modules", modules_json);
    rep.set("totalCandidates", Json::make_number(static_cast<double>(total_candidates)));
    rep.set("note", Json::make_string("候选来自运行时解密后的内存映像，仍需用调试器确认函数语义；未自动启用时 hook 保持关闭"));
    write_text_file(report_path, rep.dump(2), nullptr);
    dlog("runtime scan: 完成，候选 " + std::to_string(total_candidates) + " 个 -> " + report_path);
  }).detach();
}

}  // namespace win
}  // namespace wowmod
#endif
