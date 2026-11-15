// 见 include/wowmod/log.hpp。
// SPDX-License-Identifier: MIT
#include "wowmod/log.hpp"

#include <cstdio>
#include <mutex>
#include <string>

namespace wowmod {
namespace {

std::mutex g_mu;
LogSink g_sink = nullptr;
void* g_user = nullptr;
std::FILE* g_file = nullptr;

void emit_locked(const char* line) {
  if (g_sink) {
    g_sink(line, g_user);
    return;
  }
  std::fputs(line, stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

void emit_file_locked(const char* line) {
  if (!g_file) return;
  std::fputs(line, g_file);
  std::fputc('\n', g_file);
  std::fflush(g_file);
}

}  // namespace

void set_log_sink(LogSink sink, void* user) {
  std::lock_guard<std::mutex> lk(g_mu);
  g_sink = sink;
  g_user = user;
}

void set_log_file(const std::string& path) {
  std::lock_guard<std::mutex> lk(g_mu);
  if (g_file) {
    std::fclose(g_file);
    g_file = nullptr;
  }
  if (path.empty()) return;
  g_file = std::fopen(path.c_str(), "wb");
}

void log_line(const std::string& line) {
  std::lock_guard<std::mutex> lk(g_mu);
  emit_locked(line.c_str());
  emit_file_locked(line.c_str());
}

void logf(const char* fmt, ...) {
  if (!fmt) return;
  char buf[4096];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  std::lock_guard<std::mutex> lk(g_mu);
  emit_locked(buf);
  emit_file_locked(buf);
}

}  // namespace wowmod
