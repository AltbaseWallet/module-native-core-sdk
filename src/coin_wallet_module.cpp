#include "privacy_light_wallet.hpp"
#include "protocol.hpp"
#include "wallet_secret.hpp"

#if defined(ALTBASE_ZANO_WALLET_EXPORTS)
#include "zano_wallet_api.hpp"
#define ALTBASE_COIN_WALLET_API ALTBASE_ZANO_WALLET_API
#define ALTBASE_COIN_WALLET_CALL ALTBASE_ZANO_WALLET_CALL
#define ALTBASE_COIN_WALLET_REQUEST altbase_zano_wallet_request
#define ALTBASE_COIN_WALLET_FREE altbase_zano_wallet_free
constexpr const char* kModuleCoin = "zano";
#elif defined(ALTBASE_EPIC_WALLET_EXPORTS)
#include "epic_wallet_api.hpp"
#define ALTBASE_COIN_WALLET_API ALTBASE_EPIC_WALLET_API
#define ALTBASE_COIN_WALLET_CALL ALTBASE_EPIC_WALLET_CALL
#define ALTBASE_COIN_WALLET_REQUEST altbase_epic_wallet_request
#define ALTBASE_COIN_WALLET_FREE altbase_epic_wallet_free
constexpr const char* kModuleCoin = "epic";
#else
#error A coin wallet export definition is required
#endif

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

}  // namespace

ALTBASE_COIN_WALLET_API char* ALTBASE_COIN_WALLET_CALL ALTBASE_COIN_WALLET_REQUEST(const char* request) {
  std::string id = kModuleCoin;
  try {
    std::string error;
    auto parsed = altbase::parse_request(request ? request : "", error);
    if (!parsed.has_value()) return copy_response(altbase::error_response(id, "bad-request", error));

    id = parsed->id.empty() ? id : parsed->id;
    const auto coin = parsed->params.find("coin");
    if (coin == parsed->params.end() || coin->second != kModuleCoin) {
      return copy_response(altbase::error_response(id, "bad-coin", "request was routed to the wrong coin module"));
    }

    if (parsed->method == "privacyLightWallet") {
      return copy_response(altbase::ok_response(id, fields_from_result(altbase::privacy_light_wallet(parsed->params))));
    }
    if (parsed->method == "privacyScope") {
      const auto secret = altbase::privacy_wallet_secret(parsed->params);
      return copy_response(altbase::ok_response(id, {
        {"enginePassword", secret.engine_password},
        {"scope", secret.scope},
        {"payload", secret.payload},
      }));
    }
    return copy_response(altbase::error_response(id, "bad-method", "unsupported coin wallet method"));
  } catch (const std::exception& ex) {
    return copy_response(altbase::error_response(id, "coin-wallet-error", ex.what()));
  } catch (...) {
    return copy_response(altbase::error_response(id, "coin-wallet-error", "unknown coin wallet failure"));
  }
}

ALTBASE_COIN_WALLET_API void ALTBASE_COIN_WALLET_CALL ALTBASE_COIN_WALLET_FREE(char* value) {
  std::free(value);
}
