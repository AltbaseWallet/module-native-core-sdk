#include "native_http.hpp"
#include "net_module_api.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

using Bytes = std::vector<uint8_t>;

std::string json_escape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const auto ch : value) {
    switch (ch) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) out += ' ';
        else out.push_back(ch);
    }
  }
  return out;
}

std::string base64_encode(const Bytes& data) {
  static constexpr char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (size_t i = 0; i < data.size(); i += 3) {
    const size_t remaining = data.size() - i;
    const uint32_t a = data[i];
    const uint32_t b = remaining > 1 ? data[i + 1] : 0;
    const uint32_t c = remaining > 2 ? data[i + 2] : 0;
    const uint32_t triple = (a << 16U) | (b << 8U) | c;
    out.push_back(alphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(alphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(remaining > 1 ? alphabet[(triple >> 6U) & 0x3fU] : '=');
    out.push_back(remaining > 2 ? alphabet[triple & 0x3fU] : '=');
  }
  return out;
}

std::optional<Bytes> base64_decode(const std::string& text) {
  auto value_of = [](char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
  };

  Bytes out;
  int value = 0;
  int bits = -8;
  for (const auto ch : text) {
    if (ch == '=') break;
    const auto v = value_of(ch);
    if (v < 0) continue;
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 0) {
      out.push_back(static_cast<uint8_t>((value >> bits) & 0xff));
      bits -= 8;
    }
  }
  return out;
}

std::optional<size_t> find_field_value(const std::string& json, const std::string& key) {
  const auto needle = "\"" + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return std::nullopt;
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return std::nullopt;
  ++pos;
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
  if (pos >= json.size()) return std::nullopt;
  return pos;
}

std::string json_unescape_string(const std::string& text, size_t start) {
  if (start >= text.size() || text[start] != '"') return "";
  std::string out;
  bool escaped = false;
  for (size_t i = start + 1; i < text.size(); ++i) {
    const auto ch = text[i];
    if (escaped) {
      switch (ch) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: out.push_back(ch); break;
      }
      escaped = false;
    } else if (ch == '\\') {
      escaped = true;
    } else if (ch == '"') {
      return out;
    } else {
      out.push_back(ch);
    }
  }
  return "";
}

std::string json_string_field(const std::string& json, const std::string& key, const std::string& fallback = "") {
  const auto start = find_field_value(json, key);
  if (!start || json[*start] != '"') return fallback;
  return json_unescape_string(json, *start);
}

int json_int_field(const std::string& json, const std::string& key, int fallback = 0) {
  const auto start = find_field_value(json, key);
  if (!start) return fallback;
  int value = 0;
  bool any = false;
  for (size_t i = *start; i < json.size() && json[i] >= '0' && json[i] <= '9'; ++i) {
    any = true;
    value = value * 10 + (json[i] - '0');
  }
  return any ? value : fallback;
}

std::string call_net_core(const std::string& request) {
  char* raw = altbase_net_request(request.c_str());
  if (!raw) throw std::runtime_error("network module returned no response");
  std::string response(raw);
  altbase_net_free(raw);
  return response;
}

HttpResponse request_module(
  const std::string& method,
  const std::string& url,
  const std::string& body,
  unsigned long timeout_ms,
  const std::string& content_type
) {
  const Bytes body_bytes(body.begin(), body.end());
  std::ostringstream request;
  request << "{\"method\":\"" << json_escape(method) << "\","
          << "\"url\":\"" << json_escape(url) << "\","
          << "\"bodyB64\":\"" << base64_encode(body_bytes) << "\","
          << "\"contentType\":\"" << json_escape(content_type) << "\","
          << "\"timeoutMs\":" << timeout_ms << "}";

  const auto response = call_net_core(request.str());
  const auto error = json_string_field(response, "error");
  if (!error.empty()) throw std::runtime_error(error);
  const auto body_b64 = json_string_field(response, "bodyB64");
  const auto decoded = base64_decode(body_b64);
  if (!decoded.has_value()) throw std::runtime_error("network module returned invalid body");
  return {json_int_field(response, "status", 0), std::string(decoded->begin(), decoded->end()), {}};
}

}  // namespace

HttpResponse http_get(const std::string& url, unsigned long timeout_ms) {
  return request_module("GET", url, "", timeout_ms, "");
}

HttpResponse http_post_json(const std::string& url, const std::string& body, unsigned long timeout_ms) {
  return request_module("POST", url, body, timeout_ms, "application/json");
}

HttpResponse http_post_binary(const std::string& url, const std::string& body, unsigned long timeout_ms) {
  return request_module("POST", url, body, timeout_ms, "application/octet-stream");
}

}  // namespace altbase
