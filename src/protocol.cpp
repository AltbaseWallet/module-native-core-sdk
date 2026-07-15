#include "protocol.hpp"

#include <cctype>
#include <cstdint>
#include <sstream>

namespace altbase {
namespace {

void skip_ws(const std::string& s, size_t& i) {
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])) != 0) ++i;
}

bool consume(const std::string& s, size_t& i, char expected) {
  skip_ws(s, i);
  if (i >= s.size() || s[i] != expected) return false;
  ++i;
  return true;
}

std::optional<uint16_t> parse_hex4(const std::string& s, size_t& i) {
  if (i + 4 > s.size()) return std::nullopt;
  uint16_t value = 0;
  for (int n = 0; n < 4; ++n) {
    const char ch = s[i++];
    uint16_t digit = 0;
    if (ch >= '0' && ch <= '9') digit = static_cast<uint16_t>(ch - '0');
    else if (ch >= 'a' && ch <= 'f') digit = static_cast<uint16_t>(ch - 'a' + 10);
    else if (ch >= 'A' && ch <= 'F') digit = static_cast<uint16_t>(ch - 'A' + 10);
    else return std::nullopt;
    value = static_cast<uint16_t>((value << 4U) | digit);
  }
  return value;
}

void append_utf8(std::string& out, uint32_t codepoint) {
  if (codepoint <= 0x7fU) {
    out.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7ffU) {
    out.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
    out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
  } else if (codepoint <= 0xffffU) {
    out.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
  } else {
    out.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
  }
}

std::optional<std::string> parse_string(const std::string& s, size_t& i) {
  skip_ws(s, i);
  if (i >= s.size() || s[i] != '"') return std::nullopt;
  ++i;

  std::string out;
  while (i < s.size()) {
    const char c = s[i++];
    if (c == '"') return out;
    if (c != '\\') {
      if (static_cast<unsigned char>(c) < 0x20U) return std::nullopt;
      out.push_back(c);
      continue;
    }
    if (i >= s.size()) return std::nullopt;
    const char e = s[i++];
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
        const auto first = parse_hex4(s, i);
        if (!first.has_value()) return std::nullopt;
        uint32_t codepoint = *first;
        if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
          if (i + 2 > s.size() || s[i] != '\\' || s[i + 1] != 'u') return std::nullopt;
          i += 2;
          const auto second = parse_hex4(s, i);
          if (!second.has_value() || *second < 0xdc00U || *second > 0xdfffU) return std::nullopt;
          codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (*second - 0xdc00U);
        } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
          return std::nullopt;
        }
        append_utf8(out, codepoint);
        break;
      }
      default: return std::nullopt;
    }
  }
  return std::nullopt;
}

bool valid_json_number(const std::string& value) {
  size_t i = 0;
  if (i < value.size() && value[i] == '-') ++i;
  if (i >= value.size()) return false;
  if (value[i] == '0') {
    ++i;
  } else {
    if (value[i] < '1' || value[i] > '9') return false;
    while (i < value.size() && value[i] >= '0' && value[i] <= '9') ++i;
  }
  if (i < value.size() && value[i] == '.') {
    ++i;
    const size_t fraction_start = i;
    while (i < value.size() && value[i] >= '0' && value[i] <= '9') ++i;
    if (i == fraction_start) return false;
  }
  if (i < value.size() && (value[i] == 'e' || value[i] == 'E')) {
    ++i;
    if (i < value.size() && (value[i] == '+' || value[i] == '-')) ++i;
    const size_t exponent_start = i;
    while (i < value.size() && value[i] >= '0' && value[i] <= '9') ++i;
    if (i == exponent_start) return false;
  }
  return i == value.size();
}

std::optional<std::map<std::string, std::string>> parse_flat_object(const std::string& s, size_t& i) {
  std::map<std::string, std::string> out;
  if (!consume(s, i, '{')) return std::nullopt;
  skip_ws(s, i);
  if (i < s.size() && s[i] == '}') {
    ++i;
    return out;
  }

  while (i < s.size()) {
    auto key = parse_string(s, i);
    if (!key || !consume(s, i, ':')) return std::nullopt;

    skip_ws(s, i);
    std::string value;
    bool valid_value = false;
    if (i < s.size() && s[i] == '"') {
      auto parsed = parse_string(s, i);
      if (!parsed) return std::nullopt;
      value = *parsed;
      valid_value = true;
    } else {
      const size_t start = i;
      while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
      value = s.substr(start, i - start);
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) value.pop_back();
      size_t first = 0;
      while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])) != 0) ++first;
      value.erase(0, first);
      const bool keyword = value == "true" || value == "false" || value == "null";
      valid_value = keyword || valid_json_number(value);
    }
    if (!valid_value || out.contains(*key)) return std::nullopt;
    out.emplace(*key, value);

    skip_ws(s, i);
    if (i < s.size() && s[i] == ',') {
      ++i;
      continue;
    }
    if (i < s.size() && s[i] == '}') {
      ++i;
      return out;
    }
    return std::nullopt;
  }
  return std::nullopt;
}

}  // namespace

std::optional<Request> parse_request(const std::string& line, std::string& error) {
  size_t i = 0;
  if (!consume(line, i, '{')) {
    error = "request must be a JSON object";
    return std::nullopt;
  }

  Request request;
  bool has_id = false;
  bool has_method = false;
  bool has_params = false;

  while (true) {
    skip_ws(line, i);
    if (i < line.size() && line[i] == '}') {
      ++i;
      break;
    }

    const auto key = parse_string(line, i);
    if (!key.has_value() || !consume(line, i, ':')) {
      error = "request contains an invalid field";
      return std::nullopt;
    }

    if (*key == "id" || *key == "method") {
      const auto value = parse_string(line, i);
      if (!value.has_value()) {
        error = *key + " must be a string";
        return std::nullopt;
      }
      if (*key == "id") {
        if (has_id) {
          error = "request contains duplicate id";
          return std::nullopt;
        }
        request.id = *value;
        has_id = true;
      } else {
        if (has_method || value->empty()) {
          error = "request contains invalid method";
          return std::nullopt;
        }
        request.method = *value;
        has_method = true;
      }
    } else if (*key == "params") {
      if (has_params) {
        error = "request contains duplicate params";
        return std::nullopt;
      }
      const auto params = parse_flat_object(line, i);
      if (!params.has_value()) {
        error = "params must be a flat JSON object";
        return std::nullopt;
      }
      request.params = *params;
      has_params = true;
    } else {
      error = "request contains an unsupported field";
      return std::nullopt;
    }

    skip_ws(line, i);
    if (i < line.size() && line[i] == ',') {
      ++i;
      continue;
    }
    if (i < line.size() && line[i] == '}') {
      ++i;
      break;
    }
    error = "request contains invalid JSON";
    return std::nullopt;
  }

  skip_ws(line, i);
  if (i != line.size()) {
    error = "request contains trailing data";
    return std::nullopt;
  }
  if (!has_id || !has_method) {
    error = "request must include id and method";
    return std::nullopt;
  }
  return request;
}

std::string json_escape(const std::string& value) {
  std::ostringstream out;
  for (const char c : value) {
    switch (c) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) out << ' ';
        else out << c;
    }
  }
  return out.str();
}

std::string ok_response(const std::string& id, const std::map<std::string, std::string>& fields) {
  std::ostringstream out;
  out << "{\"id\":\"" << json_escape(id) << "\",\"ok\":true,\"result\":{";
  bool first = true;
  for (const auto& [key, value] : fields) {
    if (!first) out << ',';
    first = false;
    out << "\"" << json_escape(key) << "\":\"" << json_escape(value) << "\"";
  }
  out << "}}";
  return out.str();
}

std::string error_response(const std::string& id, const std::string& code, const std::string& message) {
  std::ostringstream out;
  out << "{\"id\":\"" << json_escape(id) << "\",\"ok\":false,\"error\":{"
      << "\"code\":\"" << json_escape(code) << "\","
      << "\"message\":\"" << json_escape(message) << "\"}}";
  return out.str();
}

}  // namespace altbase
