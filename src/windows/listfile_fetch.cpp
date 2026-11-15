// 见 listfile_fetch.hpp。
// SPDX-License-Identifier: MIT
#include "windows/listfile_fetch.hpp"

#include <winhttp.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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
Response get(Session* s, const std::wstring& path, uint64_t range_from = 0) {
  Response r;
  r.request = WinHttpOpenRequest(s->connect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!r.request) {
    r.error = "WinHttpOpenRequest 失败 (" + std::to_string(GetLastError()) + ")";
    return r;
  }
  DWORD no_cache = 0;
  WinHttpSetOption(r.request, WINHTTP_OPTION_DISABLE_FEATURE, &no_cache, sizeof(no_cache));
  // 续传：只要 Range 头。服务器不理它也没关系（会回 200 + 全量），
  // 调用方看 r.status 决定从哪儿开始写。
  if (range_from) {
    const std::wstring hdr = L"Range: bytes=" + std::to_wstring(range_from) + L"-\r\n";
    WinHttpAddRequestHeaders(r.request, hdr.c_str(), (DWORD)-1L,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
  }
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
  r.ok = (r.status == 200 || r.status == 206);
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

// 流式下载一个 URL 到 path（支持续传），返回已写字节数。
// 成功时 *ok=true；失败时 error 里带 HTTP 状态或系统错误。
static bool download_to(const std::string& url, const std::string& path, uint64_t* wrote,
                        std::string* error, FetchProgress* prog,
                        const std::function<void(const FetchProgress&)>* cb,
                        uint64_t base_done, uint64_t base_total) {
  *wrote = 0;
  std::string host, req_path;
  if (!split_url(url, &host, &req_path)) {
    *error = "地址无法解析: " + url;
    return false;
  }
  Session s;
  std::string err;
  if (!open_session(w(host), &s, &err)) {
    *error = err;
    return false;
  }
  // 续传：已有 .part 就带 Range
  uint64_t have = 0;
  {
    std::error_code ec;
    const auto sz = std::filesystem::file_size(std::filesystem::u8path(path + ".part"), ec);
    if (!ec) have = sz;
  }
  Response r = get(&s, w(req_path), have);
  if (!r.ok) {
    *error = r.error + "（" + host + "）";
    if (r.request) WinHttpCloseHandle(r.request);
    return false;
  }
  const uint64_t total = r.content_length ? r.content_length + (r.status == 206 ? have : 0) : 0;
  if (r.status != 206 && have) {
    // 服务器忽略了 Range，只能从头写
    have = 0;
  }
  std::FILE* f = std::fopen((path + ".part").c_str(), have ? "ab" : "wb");
  if (!f) {
    *error = "无法写入 " + path + ".part（磁盘满或没有权限）";
    WinHttpCloseHandle(r.request);
    return false;
  }
  uint64_t done = have;
  bool bad = false;
  char buf[65536];
  for (;;) {
    DWORD got = 0;
    if (!WinHttpReadData(r.request, buf, sizeof(buf), &got)) {
      bad = true;
      *error = "下载中断 (" + std::to_string(GetLastError()) + ")，已下载 " + std::to_string(done) +
               " 字节。重新点击下载可以接着下。";
      break;
    }
    if (got == 0) break;
    if (std::fwrite(buf, 1, got, f) != got) {
      bad = true;
      *error = "写盘失败（磁盘满？）";
      break;
    }
    done += got;
    if (prog && cb) {
      prog->done = base_done + done;
      prog->total = base_total ? base_total : (total ? base_done + total : 0);
      (*cb)(*prog);
      if (prog->cancel) {
        bad = true;
        *error = "已取消";
        break;
      }
    }
  }
  std::fclose(f);
  WinHttpCloseHandle(r.request);
  if (bad) return false;
  if (total && done != total) {
    *error = "下载不完整（" + std::to_string(done) + "/" + std::to_string(total) + " 字节）";
    return false;
  }
  *wrote = done;
  return true;
}

FetchResult fetch_listfile(const std::string& out_path,
                           std::function<void(const FetchProgress&)> on_progress) {
  FetchResult res;
  FetchProgress prog;
  auto report = [&](const std::string& stage, uint64_t done, uint64_t total) {
    prog.stage = stage;
    prog.done = done;
    prog.total = total;
    if (on_progress) on_progress(prog);
    return !prog.cancel;
  };

  // ============ 通路 1：GitHub Release 的现成 CSV ============
  //
  // 这是首选：一个文件、一次请求。
  // 但它的下载会 302 到 objects.githubusercontent.com，国内网络
  // 经常直接 403/超时（用户日志里就是 4 次 HTTP 403）。
  // 所以这里【绝不能】失败就返回 —— 必须落到通路 2。
  report("查询最新版本", 0, 0);
  std::vector<std::string> candidates;
  {
    Session s;
    std::string err;
    if (open_session(L"api.github.com", &s, &err)) {
      Response r = get(&s, L"/repos/wowdev/wow-listfile/releases/latest");
      if (r.ok) {
        const std::string json = read_all(r.request, 4 << 20, nullptr);
        const auto assets = release_assets(json);
        // 必须是 .csv；上游也会挂 .zip，下下来是压缩包，解析必然 0 条
        for (const char* want : {"verified-listfile.csv", "community-listfile.csv"}) {
          for (const auto& a : assets)
            if (a.name == want) candidates.push_back(a.url);
        }
      }
      if (r.request) WinHttpCloseHandle(r.request);
    }
  }

  std::string first_err;
  for (const auto& url : candidates) {
    if (prog.cancel) { res.cancelled = true; res.error = "已取消"; return res; }
    report("下载（发布页）", 0, 0);
    uint64_t got = 0;
    std::string err;
    if (!download_to(url, out_path, &got, &err, &prog, &on_progress, 0, 0)) {
      if (first_err.empty()) first_err = err;
      if (prog.cancel) { res.cancelled = true; res.error = "已取消"; return res; }
      continue;
    }
    if (got < 1000000) {
      if (first_err.empty()) first_err = "发布页文件太小(" + std::to_string(got) + " 字节)";
      continue;
    }
    std::error_code ec;
    std::filesystem::remove(std::filesystem::u8path(out_path), ec);
    std::filesystem::rename(std::filesystem::u8path(out_path + ".part"),
                            std::filesystem::u8path(out_path), ec);
    if (ec) continue;
    res.ok = true;
    res.path = out_path;
    res.bytes = got;
    res.source = url;
    return res;
  }

  // ============ 通路 2：API 直链分片 ============
  //
  // parts/*.csv 是【同样的 id;路径 格式】，而且总大小与发布页的
  // 完整版一致（约 148 MB）。关键是它们和 api.github.com 同源，
  // API 能通这里就能通 —— 用户环境里正好是这种情况。
  // 顺手解决了"只想要角色资源"的问题：全部下完后合并成一个文件。
  struct Part { std::string url; std::string name; uint64_t size = 0; };
  std::vector<Part> parts;
  {
    Session s;
    std::string err;
    if (open_session(L"api.github.com", &s, &err)) {
      Response r = get(&s, L"/repos/wowdev/wow-listfile/contents/parts");
      if (r.ok) {
        const std::string json = read_all(r.request, 4 << 20, nullptr);
        // 逐条扫 download_url + 前面的 size
        size_t p = 0;
        for (;;) {
          const size_t np = json.find("\"name\"", p);
          if (np == std::string::npos) break;
          const size_t q1 = json.find('"', json.find(':', np) + 1);
          if (q1 == std::string::npos) break;
          const size_t q2 = json.find('"', q1 + 1);
          if (q2 == std::string::npos) break;
          const std::string nm = json.substr(q1 + 1, q2 - q1 - 1);
          const std::string du = json_string_after(json, "download_url", np);
          const std::string sz = json_string_after(json, "size", np);
          if (!du.empty() && nm.size() > 4 && nm.compare(nm.size() - 4, 4, ".csv") == 0)
            parts.push_back({du, nm, sz.empty() ? 0ull : std::strtoull(sz.c_str(), nullptr, 10)});
          p = q2 + 1;
        }
      }
      if (r.request) WinHttpCloseHandle(r.request);
    }
  }
  if (!parts.empty()) {
    uint64_t total = 0;
    for (const auto& x : parts) total += x.size;
    if (!report("下载分片（备用通路）", 0, total)) { res.cancelled = true; res.error = "已取消"; return res; }
    const std::string merged = out_path + ".part";
    std::error_code ec;
    std::filesystem::remove(std::filesystem::u8path(merged), ec);
    std::FILE* outf = std::fopen(merged.c_str(), "wb");
    if (!outf) {
      res.error = "无法写入 " + merged + "（磁盘满或没有权限）";
      return res;
    }
    uint64_t base = 0;
    bool all_ok = true;
    std::string part_err;
    for (size_t i = 0; i < parts.size(); ++i) {
      // 分片各自独立命名，否则上一轮残留的 .piece.part 会被当成
      // "这一片已下载的部分"而追加，合出来的文件就是坏的。
      const std::string piece = out_path + ".piece" + std::to_string(i);
      report("下载分片（备用通路）" + std::to_string(i + 1) + "/" + std::to_string(parts.size()),
             base, total);
      // 残留比这一片还大 = 绝对是脏数据，删掉重下
      {
        std::error_code ec4;
        const std::string tmp = piece + ".part";
        const auto sz = std::filesystem::file_size(std::filesystem::u8path(tmp), ec4);
        if (!ec4 && parts[i].size && sz >= parts[i].size) std::filesystem::remove(std::filesystem::u8path(tmp), ec4);
      }
      uint64_t got = 0;
      std::string err;
      if (!download_to(parts[i].url, piece, &got, &err, &prog, &on_progress, base, total)) {
        all_ok = false;
        part_err = parts[i].name + ": " + err;
        std::filesystem::remove(std::filesystem::u8path(piece), ec);
        std::filesystem::remove(std::filesystem::u8path(piece + ".part"), ec);
        break;
      }
      std::FILE* in = std::fopen((piece + ".part").c_str(), "rb");
      if (!in) {
        all_ok = false;
        part_err = parts[i].name + ": 临时文件不见了";
        break;
      }
      char b2[65536];
      size_t n2 = 0;
      while ((n2 = std::fread(b2, 1, sizeof(b2), in)) > 0) std::fwrite(b2, 1, n2, outf);
      std::fclose(in);
      std::filesystem::remove(std::filesystem::u8path(piece + ".part"), ec);
      base += got;
    }
    std::fclose(outf);
    if (!all_ok) {
      std::filesystem::remove(std::filesystem::u8path(merged), ec);
      res.error = (first_err.empty() ? "" : ("发布页通路失败（" + first_err + "）；")) +
                  "分片通路也失败：" + part_err;
      return res;
    }
    std::filesystem::remove(std::filesystem::u8path(out_path), ec);
    std::filesystem::rename(std::filesystem::u8path(merged), std::filesystem::u8path(out_path), ec);
    if (ec) {
      res.error = "合并后重命名失败: " + ec.message();
      return res;
    }
    report("完成", base, base);
    res.ok = true;
    res.path = out_path;
    res.bytes = base;
    res.source = "parts/*.csv（API 直链，合并后）";
    return res;
  }

  res.error = (first_err.empty() ? std::string("没有可用的下载地址")
                                 : ("发布页通路失败（" + first_err + "）；备用通路也没拿到分片清单")) +
              "。若在代理环境，请确认系统代理可用（本程序走系统代理）。";
  return res;
}

}  // namespace win
}  // namespace wowmod
