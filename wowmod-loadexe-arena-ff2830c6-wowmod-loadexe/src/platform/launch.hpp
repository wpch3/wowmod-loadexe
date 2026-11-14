// 平台无关的启动接口声明。
// SPDX-License-Identifier: MIT
#pragma once

#include <string>

#include "wowmod/config.hpp"
#include "wowmod/hooks.hpp"
#include "wowmod/vfs.hpp"
#include "wowmod/version.hpp"

namespace wowmod {

struct LaunchResult {
  int code = 0;
  std::string message;
  unsigned long pid = 0;
};

// Windows: 挂起启动 -> 注入 wowmod_hook.dll -> 恢复。
// 其他平台: 返回明确提示（核心的 detect/validate/plan 依然可用）。
LaunchResult launch_game(const Config& cfg, const ClientInfo& ci, const Vfs& vfs,
                         const HookPlan& hooks, const Diagnostics& diag, bool dry_run);

}  // namespace wowmod
