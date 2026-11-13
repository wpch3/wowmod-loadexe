// 非 Windows 平台的启动占位实现：核心逻辑（detect/validate/plan/scan）完全可用。
// SPDX-License-Identifier: MIT
#include "platform/launch.hpp"

namespace wowmod {

LaunchResult launch_game(const Config&, const ClientInfo&, const Vfs&, const HookPlan&, const Diagnostics&, bool) {
  LaunchResult r;
  r.code = 1;
  r.message =
      "启动客户端并注入覆盖层需要 Windows（客户端本身是 Windows PE）。\n"
      "当前平台可用: wowmod detect / validate / plan / scan / init，\n"
      "并可用 `wowmod plan --json` 导出给 Windows 端使用。\n"
      "请在 Windows 上用 CMake + MSVC/MinGW 构建后运行 `wowmod launch`。";
  return r;
}

}  // namespace wowmod
