#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#else
#include <curl/curl.h>
#endif

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "net_module_api.hpp"

namespace {

using Bytes = std::vector<uint8_t>;

struct HttpResponse {
  int status = 0;
  std::string body;
};

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

char* duplicate_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (!out) return nullptr;
  std::memcpy(out, response.c_str(), response.size() + 1);
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

Bytes base64_decode(const std::string& text) {
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

unsigned long json_ulong_field(const std::string& json, const std::string& key, unsigned long fallback = 0) {
  const auto start = find_field_value(json, key);
  if (!start) return fallback;
  unsigned long value = 0;
  bool any = false;
  for (size_t i = *start; i < json.size() && json[i] >= '0' && json[i] <= '9'; ++i) {
    any = true;
    value = value * 10UL + static_cast<unsigned long>(json[i] - '0');
  }
  return any ? value : fallback;
}

#ifdef _WIN32
struct Handle {
  HINTERNET value = nullptr;
  ~Handle() {
    if (value) WinHttpCloseHandle(value);
  }
  explicit Handle(HINTERNET handle = nullptr) : value(handle) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  operator HINTERNET() const { return value; }
};

std::wstring utf8_to_wide(const std::string& value) {
  if (value.empty()) return L"";
  const int len = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (len <= 0) throw std::runtime_error("utf8 conversion failed");
  std::wstring out(static_cast<size_t>(len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), len);
  return out;
}

struct ParsedUrl {
  std::wstring host;
  std::wstring path;
  INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
  bool secure = true;
};

ParsedUrl parse_url(const std::string& url) {
  const auto wide = utf8_to_wide(url);
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwSchemeLength = static_cast<DWORD>(-1);
  parts.dwHostNameLength = static_cast<DWORD>(-1);
  parts.dwUrlPathLength = static_cast<DWORD>(-1);
  parts.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts)) {
    throw std::runtime_error("invalid URL");
  }
  std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
  if (parts.dwExtraInfoLength > 0) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  return {
    std::wstring(parts.lpszHostName, parts.dwHostNameLength),
    path.empty() ? L"/" : path,
    parts.nPort,
    parts.nScheme == INTERNET_SCHEME_HTTPS,
  };
}

HttpResponse do_request(
  const std::string& method,
  const std::string& url,
  const std::string& body,
  unsigned long timeout_ms,
  const std::string& content_type
) {
  const auto parsed = parse_url(url);
  Handle session(WinHttpOpen(
    L"AltbaseNativeCore/0.1",
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS,
    0
  ));
  if (!session) throw std::runtime_error("network request failed");

  WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

  Handle connect(WinHttpConnect(session, parsed.host.c_str(), parsed.port, 0));
  if (!connect) throw std::runtime_error("network request failed");

  const auto wide_method = utf8_to_wide(method);
  Handle req(WinHttpOpenRequest(
    connect,
    wide_method.c_str(),
    parsed.path.c_str(),
    nullptr,
    WINHTTP_NO_REFERER,
    WINHTTP_DEFAULT_ACCEPT_TYPES,
    parsed.secure ? WINHTTP_FLAG_SECURE : 0
  ));
  if (!req) throw std::runtime_error("network request failed");

  std::wstring headers;
  if (method == "POST") {
    headers = L"Content-Type: ";
    headers += utf8_to_wide(content_type.empty() ? "application/json" : content_type);
    headers += L"\r\n";
  }
  const void* body_ptr = body.empty() ? WINHTTP_NO_REQUEST_DATA : body.data();
  const DWORD body_len = static_cast<DWORD>(body.size());
  if (!WinHttpSendRequest(
        req,
        headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        static_cast<DWORD>(headers.size()),
        const_cast<void*>(body_ptr),
        body_len,
        body_len,
        0
      )) {
    throw std::runtime_error("network request failed");
  }
  if (!WinHttpReceiveResponse(req, nullptr)) throw std::runtime_error("network request failed");

  DWORD status = 0;
  DWORD status_size = sizeof(status);
  WinHttpQueryHeaders(
    req,
    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_HEADER_NAME_BY_INDEX,
    &status,
    &status_size,
    WINHTTP_NO_HEADER_INDEX
  );

  std::string response_body;
  for (;;) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(req, &available)) throw std::runtime_error("network request failed");
    if (available == 0) break;
    std::vector<char> chunk(available);
    DWORD read = 0;
    if (!WinHttpReadData(req, chunk.data(), available, &read)) throw std::runtime_error("network request failed");
    response_body.append(chunk.data(), chunk.data() + read);
  }

  return {static_cast<int>(status), response_body};
}
#else
std::once_flag curl_init_flag;

size_t write_body(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* body = static_cast<std::string*>(userdata);
  body->append(ptr, size * nmemb);
  return size * nmemb;
}

HttpResponse do_request(
  const std::string& method,
  const std::string& url,
  const std::string& body,
  unsigned long timeout_ms,
  const std::string& content_type
) {
  std::call_once(curl_init_flag, []() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
  });

  CURL* curl = curl_easy_init();
  if (!curl) throw std::runtime_error("curl_easy_init failed");

  std::string response_body;
  struct curl_slist* headers = nullptr;
  if (method == "POST") {
    const std::string header = std::string("Content-Type: ") + (content_type.empty() ? "application/json" : content_type);
    headers = curl_slist_append(headers, header.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "AltbaseNativeCore/0.1");
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  const CURLcode rc = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  if (headers) curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (rc != CURLE_OK) throw std::runtime_error(curl_easy_strerror(rc));

  return {static_cast<int>(status), response_body};
}
#endif

std::string handle_request(const std::string& request) {
  const auto method = json_string_field(request, "method", "GET");
  const auto url = json_string_field(request, "url");
  const auto body_bytes = base64_decode(json_string_field(request, "bodyB64"));
  const auto body = std::string(body_bytes.begin(), body_bytes.end());
  const auto content_type = json_string_field(request, "contentType");
  const auto timeout_ms = json_ulong_field(request, "timeoutMs", 30000);

  const auto response = do_request(method, url, body, timeout_ms, content_type);
  const Bytes response_bytes(response.body.begin(), response.body.end());
  std::ostringstream out;
  out << "{\"status\":" << response.status
      << ",\"bodyB64\":\"" << base64_encode(response_bytes) << "\"}";
  return out.str();
}

}  // namespace

ALTBASE_NET_API char* ALTBASE_NET_CALL altbase_net_request(const char* request) {
  try {
    return duplicate_response(handle_request(request ? std::string(request) : std::string("{}")));
  } catch (const std::exception& e) {
    return duplicate_response("{\"error\":\"" + json_escape(e.what()) + "\"}");
  } catch (...) {
    return duplicate_response("{\"error\":\"unknown network module error\"}");
  }
}

ALTBASE_NET_API void ALTBASE_NET_CALL altbase_net_free(char* value) {
  std::free(value);
}
