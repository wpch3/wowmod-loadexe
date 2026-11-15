// listfile 下载：应用自己取，不依赖 git / python / powershell。
//
// 为什么必须内置：模组要生效，必须把磁盘上的 .blp/.m2 换算成 FileDataID，
// 而唯一可靠的来源是公开的 listfile。以前这一步是一个 .cmd + git clone，
// 用户必须先装 Git、跑脚本、拼 CSV —— 只要中间一步不对，整个加载器
// 就"看不出来有问题但不生效"。做成应用内置的一个按钮，这条路才闭合。
//
// 实现要点：
//   * WinHTTP 自动使用系统代理（用户多半在代理后面）
//   * 流式写盘：147 MB 绝不进内存
//   * 支持断点续传（HTTP Range）：网断了重跑能接着下，不用从零开始
//   * 先取 release 的 manifest（很小）判断版本，再决定要不要下载
//   * 进度回调带「已下载/总大小/当前阶段」
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>

namespace wowmod {
namespace win {

struct FetchProgress {
  std::string stage;        // "查询最新版本" / "下载" / "合并" / "完成"
  uint64_t done = 0;        // 已下载字节
  uint64_t total = 0;       // 总字节（0 = 未知）
  bool   cancel = false;    // 由调用方置 true 请求取消（下一块生效）
};

struct FetchResult {
  bool ok = false;
  std::string path;         // 成功时的输出文件
  std::string error;        // 失败原因（人话）
  uint64_t bytes = 0;
  std::string source;       // 实际用的下载地址
  bool cancelled = false;
};

// 下载 listfile 到 out_path。
//
// 策略（按顺序尝试，第一个成功的就用）：
//   1. GitHub release 的 verified-listfile.csv  —— 已核验子集，72 MB，
//      覆盖所有真实游戏资源，假阳性最低
//   2. GitHub release 的 community-listfile.csv —— 完整版，147 MB
//
// 都失败时返回 error，里面写明每一步的 HTTP 状态，便于用户判断是
// "网络/代理问题" 还是 "上游换了地址"。
FetchResult fetch_listfile(const std::string& out_path,
                           std::function<void(const FetchProgress&)> on_progress);

// 只查最新版本号（用于界面显示「本地是不是旧的」）。失败返回空串。
std::string latest_listfile_tag();

}  // namespace win
}  // namespace wowmod
#endif
