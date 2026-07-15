#include "privacy_light_wallet.hpp"
#include "privacy_module_api.hpp"
#include "protocol.hpp"
#include "wallet_secret.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <string>

namespace {

char* copy_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (!out) return nullptr;
  std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}

std::map<std::string, std::string> fields_from_result(const altbase::PrivacyLightWalletResult& result) {
  return {
    {"ok", result.ok ? "true" : "false"},
    {"code", result.code},
    {"error", result.error},
    {"address", result.address},
    {"balance", result.balance},
    {"spendable", result.spendable},
    {"txid", result.txid},
    {"amount", result.amount},
    {"fee", result.fee},
    {"transactions", result.transactions},
    {"lastScannedHeight", result.last_scanned_height},
    {"scanState", result.scan_state},
    {"serverStatus", result.server_status},
    {"nativeWalletFileName", result.native_wallet_file_name},
    {"nativeWalletFileBlob", result.native_wallet_file_blob},
    {"nativeWalletFileSize", result.native_wallet_file_size},
  };
}

std::map<std::string, std::string> fields_from_scope(const altbase::PrivacyWalletSecretResult& result) {
  return {
    {"enginePassword", result.engine_password},
    {"scope", result.scope},
    {"payload", result.payload},
  };
}

}  // namespace

ALTBASE_PRIVACY_API char* ALTBASE_PRIVACY_CALL altbase_privacy_request(const char* request) {
  std::string id = "privacy";
  try {
    std::string error;
    const auto parsed = altbase::parse_request(request ? request : "", error);
    if (!parsed.has_value()) {
      return copy_response(altbase::error_response(id, "bad-request", error));
    }

    id = parsed->id.empty() ? id : parsed->id;
    if (parsed->method == "privacyLightWallet") {
      const auto result = altbase::privacy_light_wallet(parsed->params);
      return copy_response(altbase::ok_response(id, fields_from_result(result)));
    }

    if (parsed->method == "privacyScope") {
      const auto result = altbase::privacy_wallet_secret(parsed->params);
      return copy_response(altbase::ok_response(id, fields_from_scope(result)));
    }

    return copy_response(altbase::error_response(id, "bad-method", "unsupported privacy module method"));
  } catch (const std::exception& ex) {
    return copy_response(altbase::error_response(id, "privacy-module-error", ex.what()));
  } catch (...) {
    return copy_response(altbase::error_response(id, "privacy-module-error", "unknown privacy module failure"));
  }
}

ALTBASE_PRIVACY_API void ALTBASE_PRIVACY_CALL altbase_privacy_free(char* value) {
  std::free(value);
}
