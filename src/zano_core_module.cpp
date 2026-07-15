#include "zano_module_api.hpp"

#include "currency_core/account.h"
#include "wallet/plain_wallet_api.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

constexpr std::uintmax_t ZANO_CACHED_STATE_MAX_BYTES = 16ULL * 1024ULL * 1024ULL;

std::string json_escape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const auto ch : value) {
    switch (ch) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) {
          out += ' ';
        } else {
          out.push_back(ch);
        }
    }
  }
  return out;
}

std::string error_json(const std::string& message) {
  return "{\"error\":{\"message\":\"" + json_escape(message) + "\"}}";
}

char* duplicate_response(const std::string& response) {
  auto* out = static_cast<char*>(std::malloc(response.size() + 1));
  if (!out) return nullptr;
  std::memcpy(out, response.c_str(), response.size() + 1);
  return out;
}

std::optional<size_t> find_field_value(const std::string& json, const std::string& key) {
  const auto needle = "\"" + key + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) return std::nullopt;
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return std::nullopt;
  ++pos;
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
  if (pos >= json.size()) return std::nullopt;
  return pos;
}

std::string json_unescape_string(const std::string& text, size_t start, size_t* end_out = nullptr) {
  if (start >= text.size() || text[start] != '"') throw std::runtime_error("invalid JSON string");
  std::string out;
  bool escaped = false;
  for (size_t i = start + 1; i < text.size(); ++i) {
    const auto ch = text[i];
    if (escaped) {
      switch (ch) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: out.push_back(ch); break;
      }
      escaped = false;
    } else if (ch == '\\') {
      escaped = true;
    } else if (ch == '"') {
      if (end_out) *end_out = i + 1;
      return out;
    } else {
      out.push_back(ch);
    }
  }
  throw std::runtime_error("unterminated JSON string");
}

std::string json_string_field(const std::string& json, const std::string& key, const std::string& fallback = "") {
  const auto start = find_field_value(json, key);
  if (!start || json[*start] != '"') return fallback;
  return json_unescape_string(json, *start);
}

uint64_t json_u64_field(const std::string& json, const std::string& key, uint64_t fallback = 0) {
  const auto start = find_field_value(json, key);
  if (!start) return fallback;
  uint64_t value = 0;
  bool any = false;
  for (size_t i = *start; i < json.size() && json[i] >= '0' && json[i] <= '9'; ++i) {
    any = true;
    value = value * 10ULL + static_cast<uint64_t>(json[i] - '0');
  }
  return any ? value : fallback;
}

std::string json_raw_field(const std::string& json, const std::string& key, const std::string& fallback = "{}") {
  const auto start = find_field_value(json, key);
  if (!start) return fallback;
  const auto first = json[*start];
  if (first == '"') {
    size_t end = 0;
    (void)json_unescape_string(json, *start, &end);
    return json.substr(*start, end - *start);
  }
  if (first != '{' && first != '[') {
    auto end = *start;
    while (end < json.size() && json[end] != ',' && json[end] != '}') ++end;
    return json.substr(*start, end - *start);
  }

  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (size_t i = *start; i < json.size(); ++i) {
    const auto ch = json[i];
    if (in_string) {
      if (escaped) escaped = false;
      else if (ch == '\\') escaped = true;
      else if (ch == '"') in_string = false;
      continue;
    }
    if (ch == '"') in_string = true;
    else if (ch == '{' || ch == '[') ++depth;
    else if (ch == '}' || ch == ']') {
      --depth;
      if (depth == 0) return json.substr(*start, i - *start + 1);
    }
  }
  return fallback;
}

std::vector<uint8_t> base64_decode(const std::string& text) {
  auto value_of = [](char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
  };

  std::vector<uint8_t> out;
  int value = 0;
  int bits = -8;
  for (const auto ch : text) {
    if (ch == '=') break;
    const auto v = value_of(ch);
    if (v < 0) continue;
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 0) {
      out.push_back(static_cast<uint8_t>((value >> bits) & 0xff));
      bits -= 8;
    }
  }
  return out;
}

std::string base64_encode(const std::vector<uint8_t>& bytes) {
  static constexpr char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);
  for (size_t i = 0; i < bytes.size(); i += 3) {
    const size_t remaining = bytes.size() - i;
    const uint32_t a = bytes[i];
    const uint32_t b = remaining > 1 ? bytes[i + 1] : 0;
    const uint32_t c = remaining > 2 ? bytes[i + 2] : 0;
    const uint32_t value = (a << 16) | (b << 8) | c;
    out.push_back(alphabet[(value >> 18) & 0x3f]);
    out.push_back(alphabet[(value >> 12) & 0x3f]);
    out.push_back(remaining > 1 ? alphabet[(value >> 6) & 0x3f] : '=');
    out.push_back(remaining > 2 ? alphabet[value & 0x3f] : '=');
  }
  return out;
}

bool zano_wallet_file_is_prepared(std::uintmax_t size) {
  return size >= 4096;
}

std::uintmax_t safe_file_size(const std::filesystem::path& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  return ec ? 0 : size;
}

bool response_has_error(const std::string& response) {
  return response.find("\"error\"") != std::string::npos
    && response.find("\"error\":null") == std::string::npos;
}

bool zano_wallet_file_name_is_safe(const std::string& file_name, const std::string& scope) {
  if (file_name.empty()) return false;
  if (file_name.find('/') != std::string::npos || file_name.find('\\') != std::string::npos || file_name.find(':') != std::string::npos) {
    return false;
  }
  if (file_name.rfind("altbase-zano-", 0) != 0) return false;
  if (file_name.find(scope) == std::string::npos) return false;
  return std::filesystem::path(file_name).extension() == ".zan";
}

bool install_cached_wallet_state(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& file_name,
  const std::string& encoded_state
) {
  if (encoded_state.empty() || !zano_wallet_file_name_is_safe(file_name, scope)) return false;
  const auto decoded = base64_decode(encoded_state);
  if (!zano_wallet_file_is_prepared(decoded.size()) || decoded.size() > ZANO_CACHED_STATE_MAX_BYTES) return false;

  const auto wallets_dir = work_dir / "wallets";
  std::error_code ec;
  std::filesystem::create_directories(wallets_dir, ec);
  if (ec) return false;

  const auto target = wallets_dir / file_name;
  const auto existing_size = safe_file_size(target);
  if (zano_wallet_file_is_prepared(existing_size) && existing_size >= decoded.size()) return false;

  auto temporary = target;
  temporary += ".restore";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output.write(reinterpret_cast<const char*>(decoded.data()), static_cast<std::streamsize>(decoded.size()));
    output.flush();
    if (!output) {
      output.close();
      std::filesystem::remove(temporary, ec);
      return false;
    }
  }

  ec.clear();
  std::filesystem::rename(temporary, target, ec);
  if (ec) {
    ec.clear();
    std::filesystem::remove(target, ec);
    ec.clear();
    std::filesystem::rename(temporary, target, ec);
  }
  if (ec) {
    std::filesystem::remove(temporary, ec);
    return false;
  }
  return true;
}

std::string read_cached_wallet_state(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& file_name
) {
  if (!zano_wallet_file_name_is_safe(file_name, scope)) return "{}";
  const auto path = work_dir / "wallets" / file_name;
  const auto size = safe_file_size(path);
  if (!zano_wallet_file_is_prepared(size) || size > ZANO_CACHED_STATE_MAX_BYTES) return "{}";

  std::ifstream input(path, std::ios::binary);
  if (!input) return "{}";
  std::vector<uint8_t> bytes(static_cast<size_t>(size));
  input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!input || static_cast<size_t>(input.gcount()) != bytes.size()) return "{}";

  return "{\"fileName\":\"" + json_escape(file_name)
    + "\",\"stateB64\":\"" + base64_encode(bytes)
    + "\",\"size\":" + std::to_string(size) + "}";
}

struct ZanoWalletFileChoice {
  std::string file_name;
  bool exists = false;
  std::uintmax_t size = 0;
};

ZanoWalletFileChoice choose_zano_wallet_file(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& preferred_file_name
) {
  const auto wallets_dir = work_dir / "wallets";
  const auto preferred_path = wallets_dir / preferred_file_name;
  ZanoWalletFileChoice preferred{preferred_file_name, false, 0};

  std::error_code ec;
  if (std::filesystem::exists(preferred_path, ec)) {
    preferred.exists = true;
    preferred.size = safe_file_size(preferred_path);
    if (zano_wallet_file_is_prepared(preferred.size)) return preferred;
  }

  if (!std::filesystem::exists(wallets_dir, ec)) return preferred;

  ZanoWalletFileChoice best = preferred;
  bool found_prepared = false;
  for (const auto& entry : std::filesystem::directory_iterator(wallets_dir, ec)) {
    if (ec) break;
    std::error_code entry_ec;
    if (!entry.is_regular_file(entry_ec) || entry_ec) continue;
    const auto path = entry.path();
    const auto file_name = path.filename().string();
    if (!zano_wallet_file_name_is_safe(file_name, scope)) continue;

    const auto size = safe_file_size(path);
    if (!zano_wallet_file_is_prepared(size)) continue;
    if (!found_prepared || size > best.size) {
      best = {file_name, true, size};
      found_prepared = true;
    }
  }

  return found_prepared ? best : preferred;
}

std::string append_wallet_choice_fields(
  std::string response,
  const std::string& file_name,
  bool wallet_exists
) {
  if (response.empty() || response.front() != '{' || response.back() != '}') return response;
  response.pop_back();
  if (response.size() > 1) response += ',';
  response += "\"fileName\":\"" + json_escape(file_name) + "\",";
  response += std::string("\"walletExists\":") + (wallet_exists ? "true" : "false");
  response += '}';
  return response;
}

std::string handle_request(const std::string& request) {
  const auto op = json_string_field(request, "op");
  if (op == "address") {
    const auto secret_bytes = base64_decode(json_string_field(request, "secretDerivationB64"));
    const std::string secret_derivation(secret_bytes.begin(), secret_bytes.end());
    currency::account_base account;
    if (!account.restore_from_secret_derivation(secret_derivation, false, 0)) {
      throw std::runtime_error("Zano account derivation failed");
    }
    return "{\"address\":\"" + json_escape(account.get_public_address_str()) + "\"}";
  }
  if (op == "init") {
    return plain_wallet::init(
      json_string_field(request, "host"),
      json_string_field(request, "port"),
      json_string_field(request, "workDir"),
      static_cast<int>(json_u64_field(request, "logLevel", 0))
    );
  }
  if (op == "reset") {
    return plain_wallet::reset();
  }
  if (op == "open") {
    return plain_wallet::open(
      json_string_field(request, "fileName"),
      json_string_field(request, "password")
    );
  }
  if (op == "restore") {
    const auto secret_bytes = base64_decode(json_string_field(request, "secretDerivationB64"));
    const std::string secret_derivation(secret_bytes.begin(), secret_bytes.end());
    return plain_wallet::restore(
      json_string_field(request, "fileName"),
      json_string_field(request, "password"),
      secret_derivation,
      false,
      json_u64_field(request, "restoreFrom", 0),
      json_u64_field(request, "restoreHeight", 0)
    );
  }
  if (op == "openOrRestore") {
    const auto work_dir = std::filesystem::path(json_string_field(request, "workDir"));
    const auto scope = json_string_field(request, "scope");
    const auto preferred_file_name = json_string_field(request, "preferredFileName");
    if (!zano_wallet_file_name_is_safe(preferred_file_name, scope)) {
      throw std::runtime_error("invalid Zano wallet file name");
    }

    const auto cached_state_installed = install_cached_wallet_state(
      work_dir,
      scope,
      preferred_file_name,
      json_string_field(request, "cachedStateB64")
    );
    auto wallet_choice = choose_zano_wallet_file(work_dir, scope, preferred_file_name);
    if (wallet_choice.exists && !zano_wallet_file_is_prepared(wallet_choice.size)) {
      std::error_code remove_error;
      std::filesystem::remove(work_dir / "wallets" / wallet_choice.file_name, remove_error);
      wallet_choice.exists = false;
      wallet_choice.size = 0;
    }

    const auto password = json_string_field(request, "password");
    std::string response;
    if (wallet_choice.exists) {
      response = plain_wallet::open(wallet_choice.file_name, password);
      if (cached_state_installed && wallet_choice.file_name == preferred_file_name && response_has_error(response)) {
        std::error_code remove_error;
        std::filesystem::remove(work_dir / "wallets" / wallet_choice.file_name, remove_error);
        wallet_choice = {preferred_file_name, false, 0};
        const auto secret_bytes = base64_decode(json_string_field(request, "secretDerivationB64"));
        const std::string secret_derivation(secret_bytes.begin(), secret_bytes.end());
        response = plain_wallet::restore(
          wallet_choice.file_name,
          password,
          secret_derivation,
          false,
          json_u64_field(request, "restoreFrom", 0),
          json_u64_field(request, "restoreHeight", 0)
        );
      }
    } else {
      const auto secret_bytes = base64_decode(json_string_field(request, "secretDerivationB64"));
      const std::string secret_derivation(secret_bytes.begin(), secret_bytes.end());
      response = plain_wallet::restore(
        wallet_choice.file_name,
        password,
        secret_derivation,
        false,
        json_u64_field(request, "restoreFrom", 0),
        json_u64_field(request, "restoreHeight", 0)
      );
    }
    return append_wallet_choice_fields(response, wallet_choice.file_name, wallet_choice.exists);
  }
  if (op == "walletState") {
    return read_cached_wallet_state(
      std::filesystem::path(json_string_field(request, "workDir")),
      json_string_field(request, "scope"),
      json_string_field(request, "fileName")
    );
  }
  if (op == "syncCall") {
    return plain_wallet::sync_call(
      json_string_field(request, "method"),
      json_u64_field(request, "walletId", 0),
      json_raw_field(request, "params", "{}")
    );
  }
  if (op == "invoke") {
    return plain_wallet::invoke(
      json_u64_field(request, "walletId", 0),
      json_raw_field(request, "request", "{}")
    );
  }
  throw std::runtime_error("unsupported Zano module operation");
}

}  // namespace

ALTBASE_ZANO_API char* ALTBASE_ZANO_CALL altbase_zano_request(const char* request) {
  try {
    return duplicate_response(handle_request(request ? std::string(request) : std::string("{}")));
  } catch (const std::exception& e) {
    return duplicate_response(error_json(e.what()));
  } catch (...) {
    return duplicate_response(error_json("unknown Zano module error"));
  }
}

ALTBASE_ZANO_API void ALTBASE_ZANO_CALL altbase_zano_free(char* value) {
  std::free(value);
}
