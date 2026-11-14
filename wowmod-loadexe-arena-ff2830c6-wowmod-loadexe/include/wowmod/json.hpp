// 零依赖 JSON / JSONC 解析与序列化（支持注释、尾随逗号、\uXXXX）。
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace wowmod {

class Json {
 public:
  enum class Type { Null, Bool, Number, String, Array, Object };

  Type type = Type::Null;
  bool boolean = false;
  double number = 0;
  std::string text;
  std::vector<Json> array;
  std::vector<std::pair<std::string, Json>> object;

  Json() = default;
  static Json null();
  static Json make_bool(bool v);
  static Json make_number(double v);
  static Json make_string(std::string v);
  static Json make_array();
  static Json make_object();

  bool is_null() const { return type == Type::Null; }
  bool has(const std::string& key) const;
  const Json* find(const std::string& key) const;
  const Json& at(const std::string& key) const;  // 不存在返回 null Json
  const Json& index(size_t i) const;

  std::string as_string(const std::string& def = "") const;
  long long as_int(long long def = 0) const;
  bool as_bool(bool def = false) const;
  std::vector<std::string> as_string_array() const;
  const std::vector<Json>& as_array() const { return array; }

  void set(const std::string& key, Json value);
  void push(Json value);

  // 解析；失败返回 null Json 并把错误写进 err。
  static Json parse(const std::string& input, std::string* err = nullptr);
  std::string dump(int indent = 2) const;

 private:
  void dump_into(std::string* out, int indent, int level) const;
};

}  // namespace wowmod
