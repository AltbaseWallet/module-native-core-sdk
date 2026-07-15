#include "wallet_vault.hpp"

#include "wallet_secret.hpp"

#include <stdexcept>

namespace altbase {

std::map<std::string, std::string> handle_wallet_vault(const Request& request) {
  if (request.method == "health") {
    return {{"service", "altbase-vault"}, {"version", ALTBASE_CORE_VERSION}, {"status", "ok"}};
  }
  if (request.method == "generatePhrase") {
    return {{"phrase", generate_bip39_mnemonic()}};
  }
  if (request.method == "validatePhrase") {
    return {{"isValid", validate_bip39_mnemonic(request.params.count("phrase") ? request.params.at("phrase") : "") ? "true" : "false"}};
  }
  if (request.method == "createWalletSecret") {
    const auto secret = create_wallet_secret(request.params);
    return {
      {"verifyHash", secret.verify_hash}, {"verifySalt", secret.verify_salt},
      {"cipherText", secret.cipher_text}, {"iv", secret.iv}, {"salt", secret.salt},
    };
  }
  if (request.method == "verifyWalletPassword") {
    return {{"isValid", verify_wallet_password(request.params) ? "true" : "false"}};
  }
  if (request.method == "decryptWalletSecret") {
    return {{"phrase", decrypt_wallet_secret(request.params)}};
  }
  throw std::runtime_error("unknown vault method: " + request.method);
}

}  // namespace altbase
