#pragma once

#include <map>
#include <string>

namespace altbase {

struct PrivacyLightWalletResult {
  bool ok = false;
  std::string code;
  std::string error;
  std::string address;
  std::string balance;
  std::string spendable;
  std::string txid;
  std::string amount;
  std::string fee;
  std::string transactions;
  std::string last_scanned_height;
  std::string scan_state;
  std::string server_status;
  std::string native_wallet_file_name;
  std::string native_wallet_file_blob;
  std::string native_wallet_file_size;
};

struct PrivacyModuleScopeResult {
  std::string engine_password;
  std::string scope;
  std::string payload;
};

PrivacyModuleScopeResult privacy_module_scope(const std::map<std::string, std::string>& params);
PrivacyLightWalletResult privacy_light_wallet(const std::map<std::string, std::string>& params);

}  // namespace altbase
