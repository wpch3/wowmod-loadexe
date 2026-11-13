// SPDX-License-Identifier: MIT
#ifdef _WIN32
#include "windows/inject.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "wowmod/util.hpp"

namespace wowmod {
namespace win {

namespace {

std::string win_error_text(DWORD e) {
  switch (e) {
    case 2: return "ERROR_FILE_NOT_FOUND（找不到 DLL 文件）";
    case 3: return "ERROR_PATH_NOT_FOUND（路径不存在）";
    case 5: return "ERROR_ACCESS_DENIED（拒绝访问：Defender/ASR、完整性级别或受保护进程）";
    case 32: return "ERROR_SHARING_VIOLATION（文件被占用）";
    case 126: return "ERROR_MOD_NOT_FOUND（DLL 或它的依赖，例如 UCRT 运行库，找不到）";
    case 127: return "ERROR_PROC_NOT_FOUND（缺少某个导出函数）";
    case 193: return "ERROR_BAD_EXE_FORMAT（位数不符或不是有效 PE）";
    case 216: return "ERROR_EXE_MACHINE_TYPE_MISMATCH（架构不匹配）";
    case 998: return "ERROR_NOACCESS（内存访问无效）";
    case 1114: return "ERROR_DLL_INIT_FAILED（DllMain 初始化失败/返回 FALSE）";
    default: return "";
  }
}

// 读 PE 导入表，列出依赖的 DLL；api-ms-*/ext-ms-* 是系统 API Set（不是磁盘文件），跳过。
std::string dependency_report(const std::vector<uint8_t>& b) {
  auto u16 = [&](size_t o) -> uint16_t {
    return o + 2 > b.size() ? 0 : static_cast<uint16_t>(b[o] | (b[o + 1] << 8));
  };
  auto u32 = [&](size_t o) -> uint32_t {
    return o + 4 > b.size() ? 0 : static_cast<uint32_t>(b[o]) | (static_cast<uint32_t>(b[o + 1]) << 8) |
                                       (static_cast<uint32_t>(b[o + 2]) << 16) | (static_cast<uint32_t>(b[o + 3]) << 24);
  };
  size_t pe = b.size() > 0x40 ? u32(0x3C) : 0;
  if (!pe || u32(pe) != 0x00004550u) return "无法解析 PE 头";
  size_t opt = pe + 24;
  uint16_t magic = u16(opt);
  size_t dir_off = magic == 0x10B ? opt + 96 : opt + 112;
  uint32_t imp_rva = u32(dir_off + 8);
  uint16_t nsec = u16(pe + 6), optsz = u16(pe + 20);
  std::vector<std::pair<uint32_t, uint32_t>> secs;  // (rva, raw_ptr) + span
  std::vector<uint32_t> spans;
  size_t so = opt + optsz;
  for (uint16_t i = 0; i < nsec; ++i) {
    size_t o = so + 40 * static_cast<size_t>(i);
    uint32_t vs = u32(o + 8), va = u32(o + 12), rs = u32(o + 16), ro = u32(o + 20);
    secs.push_back({va, ro});
    spans.push_back(std::max(vs, rs));
  }
  auto r2o = [&](uint32_t rva) -> size_t {
    for (size_t i = 0; i < secs.size(); ++i)
      if (rva >= secs[i].first && rva - secs[i].first < spans[i]) return secs[i].second + (rva - secs[i].first);
    return rva < b.size() && (secs.empty() || rva < secs[0].first) ? rva : static_cast<size_t>(-1);
  };
  size_t io = r2o(imp_rva);
  if (io == static_cast<size_t>(-1)) return "无导入表";
  std::vector<std::string> deps;
  for (size_t o = io; o + 20 <= b.size(); o += 20) {
    uint32_t name_rva = u32(o + 12);
    if (!name_rva) break;
    size_t no = r2o(name_rva);
    if (no == static_cast<size_t>(-1) || no >= b.size()) continue;
    std::string name;
    for (size_t p = no; p < b.size() && b[p] && name.size() < 128; ++p) name.push_back(static_cast<char>(b[p]));
    if (name.empty()) continue;
    std::string lower = to_lower(name);
    if (starts_with(lower, "api-ms-") || starts_with(lower, "ext-ms-")) continue;
    if (std::find(deps.begin(), deps.end(), name) == deps.end()) deps.push_back(name);
  }
  if (deps.empty()) return "仅依赖系统 API Set（UCRT / KERNEL32）";
  std::string out;
  for (const auto& d : deps) {
    std::wstring w = utf8_to_wide(d);
    bool ok = GetModuleHandleW(w.c_str()) != nullptr;
    if (!ok) {
      HMODULE h = LoadLibraryExW(w.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
      ok = h != nullptr;
      if (h) FreeLibrary(h);
    }
    out += (ok ? "[OK] " : "[缺失] ") + d + "  ";
  }
  return out;
}

// 不执行 DllMain、不解析依赖地把 DLL 映射进自身进程，用来排除「位数/PE 格式」问题。
std::string preflight(const std::wstring& dll) {
  SetLastError(0);
  HMODULE h = LoadLibraryExW(dll.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  DWORD e = GetLastError();
  if (!h) return "本地 PE 预检失败 GetLastError=" + std::to_string(e) + " " + win_error_text(e);
  FreeLibrary(h);
  return "本地 PE 预检通过（x64/格式正确）";
}

}  // namespace

bool inject_dll(HANDLE process, const std::wstring& dll_path, std::string* err) {
  if (!process) { if (err) *err = "无效的进程句柄"; return false; }
  if (!file_exists(normalize_path(wowmod::wide_to_utf8(dll_path)))) {
    if (err) *err = "找不到注入模块: " + normalize_path(wowmod::wide_to_utf8(dll_path));
    return false;
  }
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  if (!k32) { if (err) *err = "无法取得 kernel32"; return false; }
  auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(k32, "LoadLibraryW"));
  if (!load_library) { if (err) *err = "无法解析 LoadLibraryW"; return false; }

  size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { if (err) *err = "VirtualAllocEx 失败 (" + std::to_string(GetLastError()) + ")"; return false; }
  SIZE_T written = 0;
  if (!WriteProcessMemory(process, remote, dll_path.c_str(), bytes, &written) || written != bytes) {
    if (err) *err = "WriteProcessMemory 失败 (" + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote, 0, nullptr);
  if (!thread) {
    DWORD crt_err = GetLastError();
    if (err) *err = "CreateRemoteThread 失败 (" + std::to_string(crt_err) + ") " + win_error_text(crt_err);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  DWORD wait = WaitForSingleObject(thread, 15000);
  DWORD code = 0;
  GetExitCodeThread(thread, &code);
  CloseHandle(thread);
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  if (wait == WAIT_TIMEOUT) { if (err) *err = "注入超时（DllMain 卡住 15 秒）"; return false; }
  if (code == 0) {
    std::vector<uint8_t> self_bytes;
    std::string read_err;
    read_binary_file(normalize_path(wowmod::wide_to_utf8(dll_path)), &self_bytes, &read_err);
    std::string deps = self_bytes.empty() ? "无法读取 DLL" : dependency_report(self_bytes);
    if (err) {
      *err = "LoadLibraryW 在目标进程返回 NULL（远程线程确实执行了，但加载失败）。\n" +
             std::string("  ") + preflight(dll_path) + "\n" +
             "  依赖: " + deps + "\n" +
             "  常见原因: ① 挂起阶段 loader/UCRT 尚未初始化完（建议开启 injectRetry）\n" +
             "            ② Windows Defender / ASR 拦截从 Downloads 目录注入未签名 DLL\n" +
             "            ③ DLL 位数或依赖不符 ④ 客户端有反注入保护\n" +
             "  诊断: 运行 .\\scripts\\diagnose-load.ps1 查看 GetLastError；\n" +
             "        或把 wowmod.exe / wowmod_hook.dll 移到 D:\\ 下非 Downloads 目录再试。";
    }
    return false;
  }
  if (err) *err = "注入成功，模块基址 0x" + to_hex(code, 8);
  return true;
}

}  // namespace win
}  // namespace wowmod
#endif
