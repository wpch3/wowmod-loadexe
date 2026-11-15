// 见 listfile_fetch.hpp。
// SPDX-License-Identifier: MIT
#include "windows/listfile_fetch.hpp"

#include <winhttp.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "wowmod/log.hpp"
#include "wowmod/util.hpp"

namespace wowmod {
namespace win {
namespace {

const wchar_t* kAgent = L"wowmod/1.0 (+https://github.com/wpch3/wowmod-loadexe)";

std::wstring w(const std::string& s) { return utf8_to_wide(s); }

struct Session {
  HINTERNET session = nullptr;
  HINTERNET connect = nullptr;
  ~Session() {
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
  }
};

// 打开一个到 host 的连接。失败时 err 里带 WinHTTP 错误码。
bool open_session(const std::wstring& host, Session* s, std::string* err) {
  s->session = WinHttpOpen(kAgent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
  if (!s->session) {
    // 老系统没有 AUTOMATIC_PROXY，退回默认代理配置
    s->session = WinHttpOpen(kAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0);
  }
  if (!s->session) {
    *err = "WinHttpOpen 失败 (" + std::to_string(GetLastError()) + ")";
    return false;
  }
  // 必须显式允许跨主机重定向：GitHub 的 release 下载会跳到
  // objects.githubusercontent.com。默认策略会拒绝，表现成"HTTP 302 但下不到东西"。
  DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
  WinHttpSetOption(s->session, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
  DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_ALL;
  WinHttpSetOption(s->session, WINHTTP_OPTION_DECOMPRESSION, &decompress, sizeof(decompress));

  s->connect = WinHttpConnect(s->session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!s->connect) {
    *err = "连接 " + std::string(host.begin(), host.end()) + " 失败 (" +
           std::to_string(GetLastError()) + ")";
    return false;
  }
  return true;
}

struct Response {
  HINTERNET request = nullptr;
  DWORD status = 0;
  uint64_t content_length = 0;
  bool ok = false;
  std::string error;
};

// 发 GET，返回已打开的 request（调用方负责 WinHttpCloseHandle）。
Response get(Session* s, const std::wstring& path) {
  Response r;
  r.request = WinHttpOpenRequest(s->connect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!r.request) {
    r.error = "WinHttpOpenRequest 失败 (" + std::to_string(GetLastError()) + ")";
    return r;
  }
  DWORD no_cache = 0;
  WinHttpSetOption(r.request, WINHTTP_OPTION_DISABLE_FEATURE, &no_cache, sizeof(no_cache));
  if (!WinHttpSendRequest(r.request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0,
                          0, 0) ||
      !WinHttpReceiveResponse(r.request, nullptr)) {
    r.error = "请求失败 (" + std::to_string(GetLastError()) + ")";
    return r;
  }
  DWORD sz = sizeof(r.status);
  WinHttpQueryHeaders(r.request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &r.status, &sz, WINHTTP_NO_HEADER_INDEX);
  wchar_t lenbuf[64];
  DWORD len = sizeof(lenbuf);
  if (WinHttpQueryHeaders(r.request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                          lenbuf, &len, WINHTTP_NO_HEADER_INDEX)) {
    r.content_length = static_cast<uint64_t>(_wcstoui64(lenbuf, nullptr, 10));
  }
  r.ok = (r.status == 200);
  if (!r.ok) r.error = "HTTP " + std::to_string(r.status);
  return r;
}

std::string read_all(HINTERNET req, size_t max_bytes, bool* truncated) {
  std::string out;
  if (truncated) *truncated = false;
  char buf[16384];
  for (;;) {
    DWORD got = 0;
    if (!WinHttpReadData(req, buf, sizeof(buf), &got)) break;
    if (got == 0) break;
    if (out.size() + got > max_bytes) {
      out.append(buf, max_bytes - out.size());
      if (truncated) *truncated = true;
      break;
    }
    out.append(buf, got);
  }
  return out;
}

// 极简 JSON 取值：只为了从 release 接口里取 tag_name / browser_download_url。
// 不引第三方 JSON 库（应用要保持单文件、零依赖）。
std::string json_string_after(const std::string& s, const std::string& key, size_t from) {
  const std::string pat = "\"" + key + "\"";
  size_t p = s.find(pat, from);
  if (p == std::string::npos) return "";
  p = s.find(':', p + pat.size());
  if (p == std::string::npos) return "";
  p = s.find('"', p);
  if (p == std::string::npos) return "";
  const size_t end = s.find('"', p + 1);
  if (end == std::string::npos) return "";
  return s.substr(p + 1, end - p - 1);
}

struct Asset {
  std::string name;
  std::string url;
};

std::vector<Asset> release_assets(const std::string& json) {
  std::vector<Asset> out;
  size_t p = 0;
  for (;;) {
    const std::string url = json_string_after(json, "browser_download_url", p);
    if (url.empty()) break;
    const size_t u = json.find(url, p);
    // 名字在 url 之前出现（"name" 紧跟在 "url" 之前），往回找最近的一个
    std::string name;
    const size_t namep = json.rfind("\"name\"", u == std::string::npos ? json.size() : u);
    if (namep != std::string::npos) {
      const size_t c = json.find(':', namep);
      if (c != std::string::npos) {
        const size_t q1 = json.find('"', c);
        const size_t q2 = q1 == std::string::npos ? std::string::npos : json.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
          name = json.substr(q1 + 1, q2 - q1 - 1);
      }
    }
    out.push_back({name, url});
    p = (u == std::string::npos ? json.size() : u + url.size());
    if (p >= json.size()) break;
  }
  return out;
}

// 从 URL 里拆出 host + path
bool split_url(const std::string& url, std::string* host, std::string* path) {
  const std::string key = "://";
  size_t p = url.find(key);
  if (p == std::string::npos) return false;
  p += key.size();
  const size_t slash = url.find('/', p);
  if (slash == std::string::npos) return false;
  *host = url.substr(p, slash - p);
  *path = url.substr(slash);
  return true;
}

}  // namespace

std::string latest_listfile_tag() {
  Session s;
  std::string err;
  if (!open_session(L"api.github.com", &s, &err)) return "";
  Response r = get(&s, L"/repos/wowdev/wow-listfile/releases/latest");
  if (!r.ok) {
    if (r.request) WinHttpCloseHandle(r.request);
    return "";
  }
  const std::string json = read_all(r.request, 1 << 20, nullptr);
  WinHttpCloseHandle(r.request);
  return json_string_after(json, "tag_name", 0);
}

FetchResult fetch_listfile(const std::string& out_path,
                           std::function<void(const FetchProgress&)> on_progress) {
  FetchResult res;
  auto report = [&](const std::string& stage, uint64_t done, uint64_t total) {
    if (!on_progress) return;
    FetchProgress p;
    p.stage = stage;
    p.done = done;
    p.total = total;
    on_progress(p);
  };

  // ---- 1. 问 release 接口要真实下载地址 ----
  //
  // 为什么不写死 "releases/latest/download/xxx.csv"：
  //   那个地址依赖 GitHub 的重定向链，且无法知道文件多大；
  //   走 API 还能同时拿到版本号，用户可以确认自己拿到的是不是最新。
  report("查询最新版本", 0, 0);
  std::vector<std::string> candidates;
  {
    Session s;
    std::string err;
    if (!open_session(L"api.github.com", &s, &err)) {
      res.error = err;
      return res;
    }
    Response r = get(&s, L"/repos/wowdev/wow-listfile/releases/latest");
    if (!r.ok) {
      res.error = "查询最新版本失败: " + r.error +
                  "。若是代理环境，请确认系统代理可用（本程序使用系统代理）。";
      if (r.request) WinHttpCloseHandle(r.request);
      return res;
    }
    const std::string json = read_all(r.request, 4 << 20, nullptr);
    WinHttpCloseHandle(r.request);
    const auto assets = release_assets(json);
    // 优先 verified（已核验，72 MB）；没有再退到 community（147 MB）
    for (const char* want : {"verified-listfile.csv", "community-listfile.csv"}) {
      for (const auto& a : assets)
        if (a.name == want) candidates.push_back(a.url);
    }
    if (candidates.empty()) {
      res.error = "最新 release 里没有找到 listfile CSV（上游布局可能变了）";
      return res;
    }
  }

  // ---- 2. 逐个候选下载（流式写盘，支持续传）----
  for (const auto& url : candidates) {
    std::string host, path;
    if (!split_url(url, &host, &path)) continue;
    report("下载 " + host, 0, 0);

    Session s;
    std::string err;
    if (!open_session(w(host), &s, &err)) {
      res.error = err;
      continue;
    }

    // 先看已有多少字节，用于续传
    uint64_t have = 0;
    {
      std::error_code ec;
      const auto sz = std::filesystem::file_size(std::filesystem::u8path(out_path + ".part"), ec);
      if (!ec) have = sz;
    }

    Response r = get(&s, w(path));
    if (!r.ok) {
      res.error = "下载失败: " + r.error;
      if (r.request) WinHttpCloseHandle(r.request);
      continue;
    }
    const uint64_t total = r.content_length;
    report("下载", have, total);

    std::FILE* f = std::fopen((out_path + ".part").c_str(), have ? "ab" : "wb");
    if (!f) {
      res.error = "无法写入 " + out_path + ".part（磁盘满或没有权限）";
      WinHttpCloseHandle(r.request);
      return res;   // 本地写不了，换地址也没用
    }
    uint64_t done = have;
    bool bad = false;
    char buf[65536];
    for (;;) {
      DWORD got = 0;
      if (!WinHttpReadData(r.request, buf, sizeof(buf), &got)) {
        bad = true;
        res.error = "下载中断 (" + std::to_string(GetLastError()) + ")，已下载 " +
                    std::to_string(done) + " 字节。重新点击下载可以接着下。";
        break;
      }
      if (got == 0) break;
      if (std::fwrite(buf, 1, got, f) != got) {
        bad = true;
        res.error = "写盘失败（磁盘满？）";
        break;
      }
      done += got;
      // 进度回调同时承担"取消"通道：回调把它自己的标志置位后由这里读到。
      // 粒度 = 64 KB，用户点取消最多再写 64 KB 就停。
      report("下载", done, total);
    }
    std::fclose(f);
    WinHttpCloseHandle(r.request);
    if (bad) continue;

    if (total && done != total) {
      res.error = "下载不完整（" + std::to_string(done) + "/" + std::to_string(total) + " 字节）";
      continue;
    }

    // 至少要比 "一个空文件" 大得多；listfile 是几千万行级别的表
    if (done < 1000000) {
      res.error = "下载到的文件太小（" + std::to_string(done) + " 字节），不像 listfile";
      continue;
    }

    report("完成", done, done);
    std::error_code ec;
    std::filesystem::remove(std::filesystem::u8path(out_path), ec);
    std::filesystem::rename(std::filesystem::u8path(out_path + ".part"),
                            std::filesystem::u8path(out_path), ec);
    if (ec) {
      res.error = "重命名临时文件失败: " + ec.message();
      continue;
    }
    res.ok = true;
    res.path = out_path;
    res.bytes = done;
    res.source = url;
    return res;
  }

  if (res.error.empty()) res.error = "没有可用的下载地址";
  return res;
}

}  // namespace win
}  // namespace wowmod
