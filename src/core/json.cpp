// SPDX-License-Identifier: MIT
#include "wowmod/json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace wowmod {

namespace {
const Json kNull;

class Parser {
 public:
  Parser(const std::string& s, std::string* err) : s_(s), err_(err) {}

  Json run() {
    skip();
    Json v = value(0);
    if (failed_) return Json::null();
    skip();
    if (pos_ != s_.size()) return fail("多余的内容");
    return v;
  }

 private:
  const std::string& s_;
  std::string* err_;
  size_t pos_ = 0;
  bool failed_ = false;

  Json fail(const std::string& why) {
    failed_ = true;
    if (err_ && err_->empty()) {
      size_t line = 1, col = 1;
      for (size_t i = 0; i < pos_ && i < s_.size(); ++i) {
        if (s_[i] == '\n') { ++line; col = 1; } else ++col;
      }
      *err_ = "JSON 解析失败 (行 " + std::to_string(line) + ", 列 " + std::to_string(col) + "): " + why;
    }
    return Json::null();
  }

  void skip() {
    for (;;) {
      while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\r' || s_[pos_] == '\n')) ++pos_;
      if (pos_ + 1 < s_.size() && s_[pos_] == '/' && s_[pos_ + 1] == '/') {
        pos_ += 2;
        while (pos_ < s_.size() && s_[pos_] != '\n') ++pos_;
        continue;
      }
      if (pos_ + 1 < s_.size() && s_[pos_] == '/' && s_[pos_ + 1] == '*') {
        pos_ += 2;
        while (pos_ + 1 < s_.size() && !(s_[pos_] == '*' && s_[pos_ + 1] == '/')) ++pos_;
        if (pos_ + 1 < s_.size()) pos_ += 2;
        continue;
      }
      break;
    }
  }

  bool take(char c) {
    if (pos_ < s_.size() && s_[pos_] == c) { ++pos_; return true; }
    return false;
  }

  Json value(int depth) {
    if (depth > 128) return fail("嵌套过深");
    skip();
    if (pos_ >= s_.size()) return fail("意外结束");
    char c = s_[pos_];
    if (c == '{') return object(depth);
    if (c == '[') return array(depth);
    if (c == '"') return Json::make_string(string());
    if (c == 't') { if (s_.compare(pos_, 4, "true") == 0) { pos_ += 4; return Json::make_bool(true); } return fail("无效的 true"); }
    if (c == 'f') { if (s_.compare(pos_, 5, "false") == 0) { pos_ += 5; return Json::make_bool(false); } return fail("无效的 false"); }
    if (c == 'n') { if (s_.compare(pos_, 4, "null") == 0) { pos_ += 4; return Json::null(); } return fail("无效的 null"); }
    if (c == '-' || (c >= '0' && c <= '9')) return number();
    return fail(std::string("意外的字符 '") + c + "'");
  }

  Json number() {
    size_t start = pos_;
    if (s_[pos_] == '-') ++pos_;
    while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    if (pos_ < s_.size() && s_[pos_] == '.') {
      ++pos_;
      while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }
    if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
      while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }
    std::string tok = s_.substr(start, pos_ - start);
    char* end = nullptr;
    double v = std::strtod(tok.c_str(), &end);
    if (end != tok.c_str() + tok.size()) return fail("无效的数字: " + tok);
    return Json::make_number(v);
  }

  static void append_utf8(std::string* out, uint32_t cp) {
    if (cp < 0x80) out->push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
      out->push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out->push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  uint32_t hex4() {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      if (pos_ >= s_.size()) return 0xFFFFFFFFu;
      char c = s_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
      else return 0xFFFFFFFFu;
    }
    return v;
  }

  std::string string() {
    std::string out;
    if (!take('"')) return out;
    while (pos_ < s_.size()) {
      char c = s_[pos_++];
      if (c == '"') return out;
      if (c == '\\') {
        if (pos_ >= s_.size()) break;
        char e = s_[pos_++];
        switch (e) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            uint32_t cp = hex4();
            if (cp == 0xFFFFFFFFu) { fail("无效的 \\u 转义"); return out; }
            if (cp >= 0xD800 && cp <= 0xDBFF && pos_ + 1 < s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
              pos_ += 2;
              uint32_t lo = hex4();
              if (lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            }
            append_utf8(&out, cp);
            break;
          }
          default: out.push_back(e); break;
        }
      } else {
        out.push_back(c);
      }
    }
    fail("字符串未闭合");
    return out;
  }

  Json array(int depth) {
    Json out = Json::make_array();
    take('[');
    skip();
    if (take(']')) return out;
    for (;;) {
      out.push(value(depth + 1));
      skip();
      if (take(']')) return out;
      if (!take(',')) return fail("数组缺少 ',' 或 ']'");
      skip();
      if (take(']')) return out;  // 尾随逗号
    }
  }

  Json object(int depth) {
    Json out = Json::make_object();
    take('{');
    skip();
    if (take('}')) return out;
    for (;;) {
      skip();
      if (pos_ >= s_.size() || s_[pos_] != '"') return fail("对象键必须是字符串");
      std::string key = string();
      skip();
      if (!take(':')) return fail("对象缺少 ':'");
      out.set(key, value(depth + 1));
      skip();
      if (take('}')) return out;
      if (!take(',')) return fail("对象缺少 ',' 或 '}'");
      skip();
      if (take('}')) return out;  // 尾随逗号
    }
  }
};

void dump_string(std::string* out, const std::string& s) {
  out->push_back('"');
  static const char* hex = "0123456789abcdef";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out->append("\\\""); break;
      case '\\': out->append("\\\\"); break;
      case '\b': out->append("\\b"); break;
      case '\f': out->append("\\f"); break;
      case '\n': out->append("\\n"); break;
      case '\r': out->append("\\r"); break;
      case '\t': out->append("\\t"); break;
      default:
        if (c < 0x20) { out->append("\\u00"); out->push_back(hex[c >> 4]); out->push_back(hex[c & 0xF]); }
        else out->push_back(static_cast<char>(c));
    }
  }
  out->push_back('"');
}
}  // namespace

Json Json::null() { return Json(); }
Json Json::make_bool(bool v) { Json j; j.type = Type::Bool; j.boolean = v; return j; }
Json Json::make_number(double v) { Json j; j.type = Type::Number; j.number = v; return j; }
Json Json::make_string(std::string v) { Json j; j.type = Type::String; j.text = std::move(v); return j; }
Json Json::make_array() { Json j; j.type = Type::Array; return j; }
Json Json::make_object() { Json j; j.type = Type::Object; return j; }

bool Json::has(const std::string& key) const { return find(key) != nullptr; }

const Json* Json::find(const std::string& key) const {
  if (type != Type::Object) return nullptr;
  for (const auto& kv : object) if (kv.first == key) return &kv.second;
  return nullptr;
}

const Json& Json::at(const std::string& key) const {
  const Json* p = find(key);
  return p ? *p : kNull;
}

const Json& Json::index(size_t i) const {
  return (type == Type::Array && i < array.size()) ? array[i] : kNull;
}

std::string Json::as_string(const std::string& def) const {
  if (type == Type::String) return text;
  if (type == Type::Number) { char b[64]; std::snprintf(b, sizeof(b), "%.17g", number); return b; }
  if (type == Type::Bool) return boolean ? "true" : "false";
  return def;
}

long long Json::as_int(long long def) const {
  if (type == Type::Number) return static_cast<long long>(number);
  if (type == Type::String) { char* e = nullptr; long long v = std::strtoll(text.c_str(), &e, 0); if (e && *e == '\0') return v; }
  if (type == Type::Bool) return boolean ? 1 : 0;
  return def;
}

bool Json::as_bool(bool def) const {
  if (type == Type::Bool) return boolean;
  if (type == Type::Number) return number != 0;
  if (type == Type::String) return text == "true" || text == "1" || text == "yes" || text == "on";
  return def;
}

std::vector<std::string> Json::as_string_array() const {
  std::vector<std::string> out;
  if (type == Type::Array) for (const auto& v : array) out.push_back(v.as_string());
  else if (type == Type::String) out.push_back(text);
  return out;
}

void Json::set(const std::string& key, Json value) {
  if (type != Type::Object) { type = Type::Object; object.clear(); }
  for (auto& kv : object) if (kv.first == key) { kv.second = std::move(value); return; }
  object.emplace_back(key, std::move(value));
}

void Json::push(Json value) {
  if (type != Type::Array) { type = Type::Array; array.clear(); }
  array.push_back(std::move(value));
}

Json Json::parse(const std::string& input, std::string* err) {
  if (err) err->clear();
  // 去 UTF-8 BOM
  std::string s = input;
  if (s.size() >= 3 && static_cast<unsigned char>(s[0]) == 0xEF && static_cast<unsigned char>(s[1]) == 0xBB && static_cast<unsigned char>(s[2]) == 0xBF) s.erase(0, 3);
  return Parser(s, err).run();
}

void Json::dump_into(std::string* out, int indent, int level) const {
  auto pad = [&](int l) { if (indent > 0) out->append(static_cast<size_t>(l * indent), ' '); };
  auto nl = [&](int l) { if (indent > 0) { out->push_back('\n'); pad(l); } };
  switch (type) {
    case Type::Null: out->append("null"); break;
    case Type::Bool: out->append(boolean ? "true" : "false"); break;
    case Type::Number: { char b[64]; std::snprintf(b, sizeof(b), "%.17g", number); out->append(b); break; }
    case Type::String: dump_string(out, text); break;
    case Type::Array: {
      out->push_back('[');
      for (size_t i = 0; i < array.size(); ++i) {
        if (i) out->push_back(',');
        nl(level + 1);
        array[i].dump_into(out, indent, level + 1);
      }
      if (!array.empty()) nl(level);
      out->push_back(']');
      break;
    }
    case Type::Object: {
      out->push_back('{');
      for (size_t i = 0; i < object.size(); ++i) {
        if (i) out->push_back(',');
        nl(level + 1);
        dump_string(out, object[i].first);
        out->append(indent > 0 ? ": " : ":");
        object[i].second.dump_into(out, indent, level + 1);
      }
      if (!object.empty()) nl(level);
      out->push_back('}');
      break;
    }
  }
}

std::string Json::dump(int indent) const {
  std::string out;
  dump_into(&out, indent, 0);
  return out;
}

}  // namespace wowmod
