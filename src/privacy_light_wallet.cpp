#include "privacy_light_wallet.hpp"

#include "privacy_module_api.hpp"
#include "protocol.hpp"

#include <cctype>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace altbase {
namespace {

std::string module_request(const std::string& method, const std::map<std::string, std::string>& params) {
  std::ostringstream out;
  out << "{\"id\":\"privacy\",\"method\":\"" << json_escape(method) << "\",\"params\":{";
  bool first = true;
  for (const auto& [key, value] : params) {
    if (!first) out << ',';
    first = false;
    out << "\"" << json_escape(key) << "\":\"" << json_escape(value) << "\"";
  }
  out << "}}";
  return out.str();
}

void skip_ws(const std::string& value, size_t& index) {
  while (index < value.size() && std::isspace(static_cast<unsigned char>(value[index])) != 0) ++index;
}

std::optional<std::string> parse_json_string(const std::string& value, size_t& index) {
  skip_ws(value, index);
  if (index >= value.size() || value[index] != '"') return std::nullopt;
  ++index;

  std::string out;
  while (index < value.size()) {
    const char ch = value[index++];
    if (ch == '"') return out;
    if (ch != '\\') {
      out.push_back(ch);
      continue;
    }
    if (index >= value.size()) return std::nullopt;
    const char escaped = value[index++];
    switch (escaped) {
      case '"': out.push_back('"'); break;
      case '\\': out.push_back('\\'); break;
      case '/': out.push_back('/'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      default: return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<std::string> string_field(const std::string& json, const std::string& key) {
  const auto token = "\"" + key + "\"";
  size_t search = 0;
  while (search < json.size()) {
    const auto key_pos = json.find(token, search);
    if (key_pos == std::string::npos) return std::nullopt;
    const auto colon = json.find(':', key_pos + token.size());
    if (colon == std::string::npos) return std::nullopt;
    size_t value_pos = colon + 1;
    skip_ws(json, value_pos);
    if (value_pos < json.size() && json[value_pos] == '"') {
      return parse_json_string(json, value_pos);
    }
    search = colon + 1;
  }
  return std::nullopt;
}

PrivacyLightWalletResult module_error(const std::string& code, const std::string& message) {
  PrivacyLightWalletResult result;
  result.ok = false;
  result.code = code;
  result.error = message;
  return result;
}

}  // namespace

PrivacyLightWalletResult privacy_light_wallet(const std::map<std::string, std::string>& params) {
  const auto request = module_request("privacyLightWallet", params);
  char* raw = altbase_privacy_request(request.c_str());
  if (!raw) return module_error("privacy-module-error", "privacy module returned no response");

  const std::string response(raw);
  altbase_privacy_free(raw);

  if (response.find("\"ok\":true") == std::string::npos) {
    return module_error(
      string_field(response, "code").value_or("privacy-module-error"),
      string_field(response, "message").value_or("privacy module request failed"));
  }

  PrivacyLightWalletResult result;
  result.ok = string_field(response, "ok").value_or("false") == "true";
  result.code = string_field(response, "code").value_or("");
  result.error = string_field(response, "error").value_or("");
  result.address = string_field(response, "address").value_or("");
  result.balance = string_field(response, "balance").value_or("");
  result.spendable = string_field(response, "spendable").value_or("");
  result.txid = string_field(response, "txid").value_or("");
  result.amount = string_field(response, "amount").value_or("");
  result.fee = string_field(response, "fee").value_or("");
  result.transactions = string_field(response, "transactions").value_or("");
  result.last_scanned_height = string_field(response, "lastScannedHeight").value_or("");
  result.scan_state = string_field(response, "scanState").value_or("");
  result.server_status = string_field(response, "serverStatus").value_or("");
  result.native_wallet_file_name = string_field(response, "nativeWalletFileName").value_or("");
  result.native_wallet_file_blob = string_field(response, "nativeWalletFileBlob").value_or("");
  result.native_wallet_file_size = string_field(response, "nativeWalletFileSize").value_or("");
  return result;
}

PrivacyModuleScopeResult privacy_module_scope(const std::map<std::string, std::string>& params) {
  const auto request = module_request("privacyScope", params);
  char* raw = altbase_privacy_request(request.c_str());
  if (!raw) throw std::runtime_error("privacy module returned no response");

  const std::string response(raw);
  altbase_privacy_free(raw);
  if (response.find("\"ok\":true") == std::string::npos) {
    throw std::runtime_error(string_field(response, "message").value_or("privacy module request failed"));
  }

  PrivacyModuleScopeResult result;
  result.engine_password = string_field(response, "enginePassword").value_or("");
  result.scope = string_field(response, "scope").value_or("");
  result.payload = string_field(response, "payload").value_or("");
  return result;
}

}  // namespace altbase
