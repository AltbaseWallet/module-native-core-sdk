#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace altbase {

struct WalletSecretResult {
  std::string verify_hash;
  std::string verify_salt;
  std::string cipher_text;
  std::string iv;
  std::string salt;
};

struct PrivacyWalletSecretResult {
  std::string engine_password;
  std::string scope;
  std::string payload;
};

std::string generate_bip39_mnemonic();
bool validate_bip39_mnemonic(const std::string& mnemonic);
std::vector<uint8_t> bip39_mnemonic_to_entropy(const std::string& mnemonic);
WalletSecretResult create_wallet_secret(const std::map<std::string, std::string>& params);
bool verify_wallet_password(const std::map<std::string, std::string>& params);
std::string decrypt_wallet_secret(const std::map<std::string, std::string>& params);
PrivacyWalletSecretResult privacy_wallet_secret(const std::map<std::string, std::string>& params);

}  // namespace altbase
