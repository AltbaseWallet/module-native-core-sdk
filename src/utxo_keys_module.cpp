#include "protocol.hpp"
#include "utxo_keys.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#ifndef ALTBASE_UTXO_SERVICE_REQUEST
#error ALTBASE_UTXO_SERVICE_REQUEST must name the exported request function
#endif
#ifndef ALTBASE_UTXO_SERVICE_FREE
#error ALTBASE_UTXO_SERVICE_FREE must name the exported free function
#endif

#ifdef _WIN32
#define ALTBASE_UTXO_SERVICE_API extern "C" __declspec(dllexport)
#define ALTBASE_UTXO_SERVICE_CALL __cdecl
#else
#define ALTBASE_UTXO_SERVICE_API extern "C" __attribute__((visibility("default")))
#define ALTBASE_UTXO_SERVICE_CALL
#endif

namespace {
char* copy_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (out) std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}
}

ALTBASE_UTXO_SERVICE_API char* ALTBASE_UTXO_SERVICE_CALL ALTBASE_UTXO_SERVICE_REQUEST(const char* request) {
  std::string id;
  try {
    std::string error;
    auto parsed = altbase::parse_request(request ? request : "", error);
    if (!parsed) return copy_response(altbase::error_response(id, "bad_request", error));
    id = parsed->id;
    parsed->params["requestId"] = id;
    return copy_response(altbase::ok_response(id, altbase::handle_utxo_keys(*parsed)));
  } catch (const std::exception& error) {
    return copy_response(altbase::error_response(id, "utxo_keys_error", error.what()));
  } catch (...) {
    return copy_response(altbase::error_response(id, "utxo_keys_error", "unknown UTXO key failure"));
  }
}

ALTBASE_UTXO_SERVICE_API void ALTBASE_UTXO_SERVICE_CALL ALTBASE_UTXO_SERVICE_FREE(char* value) { std::free(value); }
