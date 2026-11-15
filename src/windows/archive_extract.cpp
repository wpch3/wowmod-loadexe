// 见 archive_extract.hpp。
// SPDX-License-Identifier: MIT
#include "windows/archive_extract.hpp"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "wowmod/util.hpp"

namespace fs = std::filesystem;

namespace wowmod {
namespace win {
namespace {

std::wstring w(const std::string& s) { return utf8_to_wide(s); }

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string file_ext(const std::string& p) {
  const size_t dot = p.find_last_of('.');
  const size_t slash = p.find_last_of("/\\");
  if (dot == std::string::npos) return "";
  if (slash != std::string::npos && dot < slash) return "";
  return lower(p.substr(dot));
}

// 在一组候选路径里找第一个存在的。用于定位 7z / WinRAR。
std::string first_existing(const std::vector<std::string>& cands) {
  std::error_code ec;
  for (const auto& c : cands)
    if (fs::is_regular_file(fs::u8path(c), ec)) return c;
  return "";
}

std::string find_7z() {
  std::vector<std::string> c;
  const char* pf = std::getenv("ProgramFiles");
  const char* pf86 = std::getenv("ProgramFiles(x86)");
  const char* local = std::getenv("LOCALAPPDATA");
  if (pf) {
    c.push_back(std::string(pf) + "\\7-Zip\\7z.exe");
    c.push_back(std::string(pf) + "\\NanaZip\\NanaZip.exe");
  }
  if (pf86) c.push_back(std::string(pf86) + "\\7-Zip\\7z.exe");
  if (local) c.push_back(std::string(local) + "\\Programs\\7-Zip\\7z.exe");
  return first_existing(c);
}

std::string find_winrar() {
  std::vector<std::string> c;
  const char* pf = std::getenv("ProgramFiles");
  const char* pf86 = std::getenv("ProgramFiles(x86)");
  if (pf) c.push_back(std::string(pf) + "\\WinRAR\\UnRAR.exe");
  if (pf86) c.push_back(std::string(pf86) + "\\WinRAR\\UnRAR.exe");
  return first_existing(c);
}

// 静默跑一个命令行工具，把合并后的输出按行交给 on_line。
// 返回进程退出码，-1 表示启动失败。
int run_tool(const std::string& exe, const std::string& args, const std::string& workdir,
             std::function<void(const std::string&)> on_line) {
  // 用具名管道收 stdout + stderr。不要用 _popen —— 它会弹出控制台窗口，
  // 而且拿不到退出码以外的东西。
  SECURITY_ATTRIBUTES sa;
  ZeroMemory(&sa, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE rd = nullptr, wr = nullptr;
  if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
  SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = wr;
  si.hStdError = wr;
  si.hStdInput = nullptr;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  std::wstring cmd = L"\"" + w(exe) + L"\" " + w(args);
  std::vector<wchar_t> buf(cmd.begin(), cmd.end());
  buf.push_back(L'\0');

  const std::wstring wd = workdir.empty() ? std::wstring() : w(workdir);
  const BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
                                 CREATE_NO_WINDOW, nullptr, wd.empty() ? nullptr : wd.c_str(), &si,
                                 &pi);
  CloseHandle(wr);
  if (!ok) {
    CloseHandle(rd);
    return -1;
  }

  std::string carry;
  char buf2[4096];
  for (;;) {
    DWORD got = 0;
    if (!ReadFile(rd, buf2, sizeof(buf2), &got, nullptr) || got == 0) break;
    for (DWORD i = 0; i < got; ++i) {
      const char c = buf2[i];
      if (c == '\r') continue;
      if (c == '\n') {
        if (on_line && !carry.empty()) on_line(carry);
        carry.clear();
      } else if (carry.size() < 4000) {
        carry.push_back(c);
      }
    }
  }
  if (on_line && !carry.empty()) on_line(carry);
  CloseHandle(rd);

  WaitForSingleObject(pi.hProcess, 10 * 60 * 1000);   // 模组包不大，10 分钟足够
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return static_cast<int>(code);
}

size_t count_files(const std::string& dir) {
  std::error_code ec;
  size_t n = 0;
  if (!fs::is_directory(fs::u8path(dir), ec)) return 0;
  for (fs::recursive_directory_iterator it(fs::u8path(dir),
                                           fs::directory_options::skip_permission_denied, ec),
       end;
       !ec && it != end; it.increment(ec)) {
    if (it->is_regular_file(ec)) ++n;
  }
  return n;
}

// 用 shell 的 ZIP 解压（Windows 自带）。不需要任何外部程序。
bool unzip_via_shell(const std::string& archive, const std::string& out_dir, std::string* err) {
  IShellDispatch* shell = nullptr;
  if (FAILED(CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER, IID_IShellDispatch,
                              reinterpret_cast<void**>(&shell))) ||
      !shell) {
    *err = "无法创建 Shell 对象";
    return false;
  }
  bool ok = false;
  VARIANT v_zip, v_dest;
  VariantInit(&v_zip);
  VariantInit(&v_dest);

  const std::wstring wz = w(archive);
  const std::wstring wd = w(out_dir);
  v_zip.vt = VT_BSTR;
  v_zip.bstrVal = SysAllocString(wz.c_str());
  v_dest.vt = VT_BSTR;
  v_dest.bstrVal = SysAllocString(wd.c_str());

  Folder* src = nullptr;
  if (v_zip.bstrVal && SUCCEEDED(shell->NameSpace(v_zip, &src)) && src) {
    Folder* dst = nullptr;
    if (SUCCEEDED(shell->NameSpace(v_dest, &dst)) && dst) {
      FolderItems* items = nullptr;
      if (SUCCEEDED(src->Items(&items)) && items) {
        // 4 = FOF_NO_UI：不弹进度框、不弹覆盖确认
        VARIANT v_opts;
        v_opts.vt = VT_I4;
        v_opts.lVal = 4;
        // CopyHere 的第一个参数是 VARIANT（放 IDispatch*），不能直接传
        // FolderItems* —— shldisp.h 里签名就是 VARIANT。传错会编译不过，
        // 而且就算强转，COM 也会在运行期拒绝。
        VARIANT v_item;
        VariantInit(&v_item);
        v_item.vt = VT_DISPATCH;
        v_item.pdispVal = items;
        if (SUCCEEDED(dst->CopyHere(v_item, v_opts))) ok = true;
        VariantClear(&v_item);
        items->Release();
      }
      dst->Release();
    }
    src->Release();
  }
  if (!ok) *err = "Shell 解压失败（文件可能损坏，或不是标准 zip）";

  VariantClear(&v_zip);
  VariantClear(&v_dest);
  shell->Release();
  return ok;
}

}  // namespace

std::string archive_stem(const std::string& archive) {
  const size_t slash = archive.find_last_of("/\\");
  std::string name = (slash == std::string::npos) ? archive : archive.substr(slash + 1);
  const size_t dot = name.find_last_of('.');
  if (dot != std::string::npos && dot > 0) name = name.substr(0, dot);
  // 去掉 Windows 不允许的字符
  for (auto& c : name)
    if (c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' || c == '*' ||
        c == '/' || c == '\\')
      c = '_';
  if (name.empty()) name = "mod";
  return name;
}

ExtractResult extract_archive(const std::string& archive, const std::string& out_dir,
                              std::function<void(const std::string&)> on_line) {
  ExtractResult r;
  r.out_dir = out_dir;

  std::error_code ec;
  if (!fs::is_regular_file(fs::u8path(archive), ec)) {
    r.error = "找不到压缩包: " + archive;
    return r;
  }
  fs::create_directories(fs::u8path(out_dir), ec);

  const std::string ext = file_ext(archive);

  if (ext == ".zip") {
    std::string err;
    if (unzip_via_shell(archive, out_dir, &err)) {
      r.ok = true;
      r.tool = "shell";
    } else {
      r.error = err;
    }
  } else if (ext == ".7z" || ext == ".zip" || ext == ".rar" || ext == ".tar" || ext == ".gz") {
    const std::string z7 = find_7z();
    const std::string rar = find_winrar();
    if (!z7.empty()) {
      const int code = run_tool(z7, "x -y -o\"" + out_dir + "\" \"" + archive + "\"", out_dir,
                                on_line);
      if (code == 0) {
        r.ok = true;
        r.tool = "7z";
      } else {
        r.error = "7-Zip 返回 " + std::to_string(code);
      }
    } else if (ext == ".rar" && !rar.empty()) {
      const int code =
          run_tool(rar, "x -y \"" + archive + "\" \"" + out_dir + "\\\"", out_dir, on_line);
      if (code == 0) {
        r.ok = true;
        r.tool = "winrar";
      } else {
        r.error = "WinRAR 返回 " + std::to_string(code);
      }
    } else if (ext == ".rar") {
      r.error = "系统没有 7-Zip 也没有 WinRAR，无法解 .rar。\n"
                "请任选其一：把压缩包解压后直接「选择模组目录」，"
                "或安装 7-Zip（免费）后重试。";
    } else {
      r.error = "系统没有可用的解压工具（7-Zip）。请安装后重试，或先手动解压。";
    }
  } else {
    r.error = "不支持的压缩格式: " + ext + "（支持 .zip / .rar / .7z）";
  }

  if (r.ok) {
    // Shell 的 CopyHere 是异步的：立刻统计会得到 0，所以稍等一下。
    // 不等到"文件数稳定"不罢休，否则扫描会看到空目录。
    size_t last = 0, stable = 0;
    for (int i = 0; i < 200; ++i) {   // 最多 20 秒
      ::Sleep(100);
      const size_t n = count_files(out_dir);
      if (n > 0 && n == last) {
        if (++stable >= 3) break;
      } else {
        stable = 0;
      }
      last = n;
    }
    r.files = count_files(out_dir);
    if (r.files == 0) {
      r.ok = false;
      r.error = "解压完成但目录里没有文件（压缩包可能是空的，或工具静默失败）";
    }
  }
  return r;
}

}  // namespace win
}  // namespace wowmod
