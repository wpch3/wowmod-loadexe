// FileDataID loose-file hook 的「真正安装」环节。
//
// 同一份代码同时服务两个入口：
//   * wowmod_rt.dll（注入到客户端内部，HANDLE = 当前进程）
//   * wowmod.exe（从外部用 OpenProcess 直接改，不需要 DLL）
//
// 一次安装做这些事：
//   1. 在目标进程申请 id 表（16 字节/项）与路径字符串块，写入后改为只读；
//   2. 生成跳板代码（fileid_stub），回填表地址与 trampoline 地址；
//   3. 在目标地址安装 detour（完整指令边界 + 重定位）；
//   4. 返回可卸载句柄。
//
// 任一步失败都会回滚前面已完成的写入，不会留下半套 hook。
// SPDX-License-Identifier: MIT
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "windows/detour.hpp"
#include "wowmod/fileid_stub.hpp"

namespace wowmod {
namespace win {

struct InstallRequest {
  uint64_t hook_target = 0;           // hook 点（须是完整指令边界）
  std::string id_register = "rdx";    // FileDataID 所在寄存器
  std::string return_register = "rax";// 命中时返回路径指针的寄存器
  std::vector<std::pair<uint64_t, std::string>> entries;  // id -> 本地绝对路径
  size_t min_cover = 14;              // detour 至少覆盖多少字节
};

struct InstallReport {
  bool installed = false;
  std::string error;
  std::vector<std::string> steps;
  uint64_t id_table_va = 0;
  uint64_t string_blob_va = 0;
  uint64_t stub_va = 0;
  uint64_t trampoline_va = 0;
  size_t copy_len = 0;
  size_t entry_count = 0;
};

// 已安装的 hook（析构/remove 时把原始指令写回）。
class FileIdHook {
 public:
  FileIdHook() = default;
  ~FileIdHook() { remove(); }
  FileIdHook(const FileIdHook&) = delete;
  FileIdHook& operator=(const FileIdHook&) = delete;

  bool installed() const { return detour_.installed; }
  bool remove();
  const InstallReport& report() const { return report_; }
  void set_process(HANDLE p) { process_ = p; }

  bool install(HANDLE process, const InstallRequest& req, InstallReport* out);

 private:
  HANDLE process_ = nullptr;
  Detour detour_;
  RemoteBlock id_table_;
  RemoteBlock strings_;
  RemoteBlock stub_;
  InstallReport report_;
};

// 拦截型 detour：不解析 FileDataID，只记录"谁在访问本地文件"。
// 命中的函数会在服务器目录下留下 wowmod-intercept.log，
// 用客户端自己的真实参数告诉你 id 在第几个参数、返回什么，
// 这是判定 ABI 的可靠方式（比猜寄存器强）。
struct InterceptTarget {
  uint64_t target = 0;
  std::string tag;
};

// 安装一组拦截 detour（每个目标一侧）。日志路径由 log_path 指定（ANSI，全路径）。
// dry_run=true 时：跳板照常建好、重定位照常校验，但目标函数一个字节都不改。
bool install_interceptors(HANDLE process, const std::vector<InterceptTarget>& targets,
                          const std::string& log_path, uint64_t counter_va, uint64_t ring_va,
                          uint32_t ring_count, std::vector<Detour>* out_detours,
                          std::vector<RemoteBlock>* out_stubs, std::string* err,
                          bool dry_run = false);

// 撤掉一组拦截 detour。
void remove_interceptors(HANDLE process, std::vector<Detour>* detours,
                         std::vector<RemoteBlock>* stubs);

// 生成拦截跳板的机器码：只记录寄存器快照到环形缓冲。
//   counter_va —— 目标进程内 8 字节计数器
//   ring_va    —— 目标进程内环形缓冲（每条 64 字节）
//   ring_mask  —— 条数 - 1（必须是 2^n - 1）
std::vector<uint8_t> build_intercept_stub(uint64_t counter_va, uint64_t ring_va, uint32_t ring_mask);

// 环形缓冲单条记录的字段偏移（64 字节）
struct InterceptRecord {
  static constexpr size_t kRax = 0;
  static constexpr size_t kRcx = 8;
  static constexpr size_t kRdx = 16;
  static constexpr size_t kR8 = 24;
  static constexpr size_t kR9 = 32;
  static constexpr size_t kRsp = 40;
  static constexpr size_t kSeq = 48;
  static constexpr size_t kSize = 64;
};

// 把「相对路径 -> 本地绝对路径」映射放进目标进程（供外部模式使用）。
// 这里只负责写入，不安装 hook。
bool write_remote_string_table(HANDLE process,
                               const std::vector<std::pair<uint64_t, std::string>>& entries,
                               RemoteBlock* table_out, RemoteBlock* strings_out,
                               std::string* err);

// 紧急卸载：把已安装 detour 的原始字节写回。
// 启动器崩溃/被关掉时也要尽量撤掉补丁 —— 否则客户端会带着坏掉的函数继续跑，
// 崩溃处理路径自己再崩就变成 EXCEPTION_INTERNAL_ERROR，连日志都没了。
// 这些必须是【可重入且不分配内存】的，因为可能在异常路径上调用。
void emergency_remove_all(HANDLE process);

// 注册一个已安装的 detour，供 emergency_remove_all 使用。
void register_installed_detour(const Detour* d);

}  // namespace win
}  // namespace wowmod
#endif
