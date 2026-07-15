#include "wallet_vault_api.hpp"

#include "protocol.hpp"
#include "wallet_vault.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

namespace {
char* copy_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (out) std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}
}

ALTBASE_VAULT_API char* ALTBASE_VAULT_CALL altbase_wallet_vault_request(const char* request) {
  std::string id;
  try {
    std::string error;
    auto parsed = altbase::parse_request(request ? request : "", error);
    if (!parsed) return copy_response(altbase::error_response(id, "bad_request", error));
    id = parsed->id;
    parsed->params["requestId"] = id;
    return copy_response(altbase::ok_response(id, altbase::handle_wallet_vault(*parsed)));
  } catch (const std::exception& error) {
    return copy_response(altbase::error_response(id, "vault_error", error.what()));
  } catch (...) {
    return copy_response(altbase::error_response(id, "vault_error", "unknown vault failure"));
  }
}

ALTBASE_VAULT_API void ALTBASE_VAULT_CALL altbase_wallet_vault_free(char* value) { std::free(value); }
