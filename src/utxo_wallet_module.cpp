#include "protocol.hpp"
#include "utxo_services_api.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <set>
#include <string>

#ifndef ALTBASE_UTXO_MODULE_COIN
#error ALTBASE_UTXO_MODULE_COIN must identify the wallet module coin
#endif
#ifndef ALTBASE_UTXO_MODULE_REQUEST
#error ALTBASE_UTXO_MODULE_REQUEST must name the exported request function
#endif
#ifndef ALTBASE_UTXO_MODULE_FREE
#error ALTBASE_UTXO_MODULE_FREE must name the exported free function
#endif

#ifdef _WIN32
#define ALTBASE_UTXO_EXPORT extern "C" __declspec(dllexport)
#define ALTBASE_UTXO_CALL __cdecl
#else
#define ALTBASE_UTXO_EXPORT extern "C" __attribute__((visibility("default")))
#define ALTBASE_UTXO_CALL
#endif

namespace {

const std::set<std::string> kSupportedMethods = {
  "validateAddress",
  "addressVariantsFromLegacy",
  "addressToScript",
  "deriveAddress",
  "deriveWif",
  "signTransaction",
  "estimateFee",
  "planTransaction",
};

char* copy_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (out == nullptr) return nullptr;
  std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}

char* module_error(const std::string& id, const std::string& code, const std::string& message) {
  return copy_response(altbase::error_response(id, code, message));
}

}  // namespace

ALTBASE_UTXO_EXPORT char* ALTBASE_UTXO_CALL ALTBASE_UTXO_MODULE_REQUEST(const char* request) {
  std::string id;
  try {
    std::string parse_error;
    const auto parsed = altbase::parse_request(request ? request : "", parse_error);
    if (!parsed.has_value()) return module_error(id, "bad_request", parse_error);

    id = parsed->id;
    const auto coin = parsed->params.find("coin");
    if (coin == parsed->params.end() || coin->second != ALTBASE_UTXO_MODULE_COIN) {
      return module_error(id, "wrong_coin_module", "request was sent to a different coin module");
    }
    if (!kSupportedMethods.contains(parsed->method)) {
      return module_error(id, "unsupported_method", "method is not owned by this coin module");
    }

    using RequestFn = char* (*)(const char*);
    using FreeFn = void (*)(char*);
    RequestFn request_fn = altbase_utxo_address_request;
    FreeFn free_fn = altbase_utxo_address_free;
    if (parsed->method == "deriveAddress" || parsed->method == "deriveWif") {
      request_fn = altbase_utxo_derivation_request;
      free_fn = altbase_utxo_derivation_free;
    } else if (parsed->method == "signTransaction") {
      request_fn = altbase_utxo_signer_request;
      free_fn = altbase_utxo_signer_free;
    } else if (parsed->method == "estimateFee" || parsed->method == "planTransaction") {
      request_fn = altbase_utxo_planner_request;
      free_fn = altbase_utxo_planner_free;
    }
    char* core_response = request_fn(request);
    if (core_response == nullptr) return module_error(id, "core_error", "wallet core returned no response");
    char* response = copy_response(core_response);
    free_fn(core_response);
    return response;
  } catch (const std::exception& error) {
    return module_error(id, "module_error", error.what());
  } catch (...) {
    return module_error(id, "module_error", "unknown coin module failure");
  }
}

ALTBASE_UTXO_EXPORT void ALTBASE_UTXO_CALL ALTBASE_UTXO_MODULE_FREE(char* value) {
  std::free(value);
}

#undef ALTBASE_UTXO_EXPORT
#undef ALTBASE_UTXO_CALL
