#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace altbase {

struct WalletDerivationResult {
  std::string address;
  std::string private_key_wif;
  std::string public_key_hex;
};

struct WalletKeyMaterial {
  std::vector<uint8_t> private_key;
  std::vector<uint8_t> public_key;
};

WalletDerivationResult derive_wallet_material(const std::map<std::string, std::string>& params);
WalletKeyMaterial derive_wallet_key_material(const std::string& mnemonic, const std::string& derivation_path);

}  // namespace altbase
