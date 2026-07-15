#include "native_http.hpp"
#include "protocol.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#ifndef ALTBASE_NODE_MODULE_COIN
#error ALTBASE_NODE_MODULE_COIN must identify the node module coin
#endif
#ifndef ALTBASE_NODE_MODULE_REQUEST
#error ALTBASE_NODE_MODULE_REQUEST must name the exported request function
#endif
#ifndef ALTBASE_NODE_MODULE_FREE
#error ALTBASE_NODE_MODULE_FREE must name the exported free function
#endif

#ifdef _WIN32
#define ALTBASE_NODE_EXPORT extern "C" __declspec(dllexport)
#define ALTBASE_NODE_CALL __cdecl
#else
#define ALTBASE_NODE_EXPORT extern "C" __attribute__((visibility("default")))
#define ALTBASE_NODE_CALL
#endif

namespace {

char* copy_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (out == nullptr) return nullptr;
  std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}

char* module_error(const std::string& id, const std::string& code, const std::string& message) {
  return copy_response(altbase::error_response(id, code, message));
}

std::string parameter(const altbase::Request& request, const std::string& name) {
  const auto value = request.params.find(name);
  return value == request.params.end() ? "" : value->second;
}

unsigned long timeout_for(const altbase::Request& request) {
  const auto text = parameter(request, "timeoutMs");
  if (text.empty()) return 10'000UL;
  const auto value = std::stoul(text);
  return value < 500UL ? 500UL : value > 120'000UL ? 120'000UL : value;
}

bool is_safe_path(const std::string& path) {
  return !path.empty()
    && path.front() == '/'
    && path.find("://") == std::string::npos
    && path.find("..") == std::string::npos
    && path.find('\\') == std::string::npos;
}

std::string endpoint_for(const std::string& path) {
  if (std::string(ALTBASE_NODE_MODULE_COIN) == "zano" && path == "/json_rpc") {
    return "https://api.altbase.io/json_rpc";
  }
  return std::string("https://api.altbase.io/api/v1/") + ALTBASE_NODE_MODULE_COIN + path;
}

}  // namespace

ALTBASE_NODE_EXPORT char* ALTBASE_NODE_CALL ALTBASE_NODE_MODULE_REQUEST(const char* request) {
  std::string id;
  try {
    std::string parse_error;
    const auto parsed = altbase::parse_request(request ? request : "", parse_error);
    if (!parsed.has_value()) return module_error(id, "bad_request", parse_error);
    id = parsed->id;

    if (parsed->method != "coinNodeRequest") {
      return module_error(id, "unsupported_method", "method is not owned by this node module");
    }
    const auto coin = parameter(*parsed, "coin");
    if (coin != ALTBASE_NODE_MODULE_COIN) {
      return module_error(id, "wrong_coin_module", "request was sent to a different node module");
    }

    const auto path = parameter(*parsed, "path");
    if (!is_safe_path(path)) return module_error(id, "invalid_node_path", "node path is not allowed");
    const auto method = parameter(*parsed, "httpMethod");
    const auto url = endpoint_for(path);
    altbase::HttpResponse response;
    if (method == "GET") {
      response = altbase::http_get(url, timeout_for(*parsed));
    } else if (method == "POST") {
      response = altbase::http_post_json(url, parameter(*parsed, "body"), timeout_for(*parsed));
    } else {
      return module_error(id, "invalid_http_method", "node module accepts only GET and POST");
    }

    return copy_response(altbase::ok_response(id, {
      {"status", std::to_string(response.status)},
      {"body", response.body},
    }));
  } catch (const std::exception& error) {
    return module_error(id, "node_module_error", error.what());
  } catch (...) {
    return module_error(id, "node_module_error", "unknown node module failure");
  }
}

ALTBASE_NODE_EXPORT void ALTBASE_NODE_CALL ALTBASE_NODE_MODULE_FREE(char* value) {
  std::free(value);
}

#undef ALTBASE_NODE_EXPORT
#undef ALTBASE_NODE_CALL
