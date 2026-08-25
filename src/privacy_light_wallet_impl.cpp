#include "privacy_light_wallet.hpp"

#include "epic_module_api.hpp"
#include "native_http.hpp"
#include "wallet_secret.hpp"
#include "zano_module_api.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <dlfcn.h>
#include <limits.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif
#include <openssl/hmac.h>
#include <openssl/sha.h>
#endif

#include <secp256k1.h>

#ifndef _WIN32
#include "currency_core/account.h"
#include "currency_core/currency_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef _WIN32
#include <fstream>
#include <filesystem>
#endif

namespace altbase {
namespace {

using Bytes = std::vector<uint8_t>;

constexpr const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr std::array<uint8_t, 12> EPIC_MASTER_SEED = {'I', 'a', 'm', 'V', 'o', 'l', 'd', 'e', 'm', 'o', 'r', 't'};
constexpr std::array<uint8_t, 2> EPICBOX_VERSION_MAINNET = {1, 0};
constexpr uint64_t ZANO_ATOMIC_UNITS = 1'000'000'000'000ULL;
constexpr uint64_t ZANO_DEFAULT_FEE = 10'000'000'000ULL;
constexpr uint64_t ZANO_RESTORE_LOOKBACK_SECONDS = 4ULL * 24ULL * 60ULL * 60ULL;
constexpr int ZANO_INITIAL_SYNC_ATTEMPTS = 120;
constexpr int ZANO_BACKGROUND_WARM_ATTEMPTS = 60;
constexpr int ZANO_SEND_READY_ATTEMPTS = 90;
constexpr int ZANO_SEND_RPC_BUSY_ATTEMPTS = 90;
constexpr int ZANO_SNAPSHOT_RPC_BUSY_ATTEMPTS = 8;
constexpr int ZANO_SNAPSHOT_STORE_BUSY_ATTEMPTS = 4;
constexpr int ZANO_INITIAL_SYNC_SLEEP_MS = 500;
constexpr uint64_t ZANO_SCAN_STATE_REORG_OVERLAP = 30;
constexpr uint64_t EPIC_RECENT_RESCAN_BLOCKS = 30;
#ifndef _WIN32
constexpr std::uintmax_t EPIC_WALLET_BACKUP_MAX_BYTES = 12ULL * 1024ULL * 1024ULL;
constexpr const char* EPIC_WALLET_BACKUP_MAGIC = "ALTBASE_EPIC_WALLET_ARCHIVE_V1";
#endif

using ZanoWalletHandle = int64_t;

struct ZanoSession {
  bool initialized = false;
  bool run_requested = false;
  bool initial_sync_pending = false;
  std::string scope;
  std::string restore_tag;
  uint64_t restore_timestamp = 0;
  uint64_t restore_height = 0;
  ZanoWalletHandle wallet_id = 0;
  std::string address;
  std::string wallet_file_name;
};

std::mutex zano_mutex;
ZanoSession zano_session;

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

#ifndef _WIN32
std::string wallet_seed_file_name() {
  constexpr std::array<char, 4> suffix = {'s', 'e', 'e', 'd'};
  return std::string("wallet.") + std::string(suffix.begin(), suffix.end());
}

std::filesystem::path wallet_seed_path(const std::filesystem::path& wallet_data_dir) {
  return wallet_data_dir / wallet_seed_file_name();
}

std::string wallet_seed_archive_name() {
  return std::string("wallet_data/") + wallet_seed_file_name();
}
#endif

std::string zano_recent_history_request() {
  return "{\"offset\":0,\"count\":50,\"update_provision_info\":true,\"exclude_special_txs\":true,\"exclude_unconfirmed\":false,\"order\":\"FROM_END_TO_BEGIN\"}";
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

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
          out += "\\u00";
          constexpr char hex[] = "0123456789abcdef";
          out.push_back(hex[(static_cast<unsigned char>(ch) >> 4U) & 0x0fU]);
          out.push_back(hex[static_cast<unsigned char>(ch) & 0x0fU]);
        } else {
          out.push_back(ch);
        }
    }
  }
  return out;
}

std::string regex_string(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch match;
  return std::regex_search(json, match, pattern) ? match[1].str() : "";
}

std::string regex_number(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch match;
  return std::regex_search(json, match, pattern) ? match[1].str() : "";
}

bool json_has_error(const std::string& json) {
  return json.find("\"error\"") != std::string::npos && json.find("\"error\":null") == std::string::npos;
}

std::string json_error_message(const std::string& json) {
  const auto message = regex_string(json, "message");
  if (!message.empty()) return message;
  const auto code = regex_string(json, "code");
  if (!code.empty()) return code;
  return json.empty() ? "empty response" : json;
}

bool regex_bool(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*true");
  return std::regex_search(json, pattern);
}

std::string json_array_field(const std::string& json, const std::string& key) {
  const auto key_pos = json.find("\"" + key + "\"");
  if (key_pos == std::string::npos) return "[]";
  const auto start = json.find('[', key_pos);
  if (start == std::string::npos) return "[]";
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (size_t i = start; i < json.size(); ++i) {
    const auto ch = json[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }
    if (ch == '"') {
      in_string = true;
    } else if (ch == '[') {
      ++depth;
    } else if (ch == ']') {
      --depth;
      if (depth == 0) return json.substr(start, i - start + 1);
    }
  }
  return "[]";
}

size_t json_array_object_count(const std::string& array_json) {
  size_t count = 0;
  int array_depth = 0;
  int object_depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (const auto ch : array_json) {
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }
    if (ch == '"') {
      in_string = true;
    } else if (ch == '[') {
      ++array_depth;
    } else if (ch == ']') {
      --array_depth;
    } else if (ch == '{') {
      if (array_depth == 1 && object_depth == 0) ++count;
      ++object_depth;
    } else if (ch == '}') {
      --object_depth;
    }
  }
  return count;
}

uint64_t parse_decimal_units(const std::string& value, uint64_t scale) {
  const auto trimmed = lower(value);
  if (trimmed.empty()) throw std::runtime_error("Amount is required");
  uint64_t whole = 0;
  uint64_t frac = 0;
  uint64_t frac_scale = scale / 10;
  bool seen_dot = false;
  bool seen_digit = false;
  for (const auto ch : trimmed) {
    if (ch == '.' || ch == ',') {
      if (seen_dot) throw std::runtime_error("Invalid decimal amount");
      seen_dot = true;
      continue;
    }
    if (ch < '0' || ch > '9') throw std::runtime_error("Invalid decimal amount");
    seen_digit = true;
    const auto digit = static_cast<uint64_t>(ch - '0');
    if (!seen_dot) {
      if (whole > (UINT64_MAX - digit) / 10ULL) throw std::runtime_error("Amount is too large");
      whole = whole * 10ULL + digit;
    } else if (frac_scale > 0) {
      frac += digit * frac_scale;
      frac_scale /= 10ULL;
    } else if (digit != 0) {
      throw std::runtime_error("Too many decimal places");
    }
  }
  if (!seen_digit) throw std::runtime_error("Amount is required");
  if (whole > (UINT64_MAX - frac) / scale) throw std::runtime_error("Amount is too large");
  return whole * scale + frac;
}

std::string units_to_decimal(uint64_t units, uint64_t scale) {
  const auto whole = units / scale;
  auto frac = units % scale;
  std::string frac_text = std::to_string(frac);
  const auto width = std::to_string(scale).size() - 1;
  if (frac_text.size() < width) frac_text.insert(frac_text.begin(), width - frac_text.size(), '0');
  while (!frac_text.empty() && frac_text.back() == '0') frac_text.pop_back();
  return frac_text.empty() ? std::to_string(whole) : std::to_string(whole) + "." + frac_text;
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data);

std::string zano_secret_derivation_from_mnemonic(const std::string& mnemonic) {
  const auto entropy = bip39_mnemonic_to_entropy(mnemonic);
  const Bytes domain = {'a', 'l', 't', 'b', 'a', 's', 'e', '-', 'z', 'a', 'n', 'o', '-', 's', 'e', 'c', 'r', 'e', 't', '-', 'd', 'e', 'r', 'i', 'v', 'a', 't', 'i', 'o', 'n', '-', 'v', '1'};
  const auto material = hmac_sha512(domain, entropy);
  return std::string(material.begin(), material.begin() + 32);
}

std::string zano_address_from_mnemonic(const std::string& mnemonic);
std::string call_zano_core(const std::string& request);
std::string zano_module_wallet_state(
  const std::string& work_dir,
  const std::string& scope,
  const std::string& file_name
);

#ifdef _WIN32
std::string join_work_dir(const std::string& base, const std::string& child) {
  if (base.empty()) return child;
  const auto last = base.back();
  if (last == '\\' || last == '/') return base + child;
  return base + "\\" + child;
}

std::string zano_work_dir(const std::map<std::string, std::string>& params) {
  const auto user_data = get_param(params, "userDataDir");
  return user_data.empty() ? "zano-light" : join_work_dir(user_data, "zano-light");
}
#else
std::filesystem::path zano_work_dir(const std::map<std::string, std::string>& params) {
  const auto user_data = get_param(params, "userDataDir");
  if (!user_data.empty()) return std::filesystem::path(user_data) / "zano-light";
  return std::filesystem::current_path() / "zano-light";
}

struct ZanoWalletFileChoice {
  std::string file_name;
  bool exists = false;
  std::uintmax_t size = 0;
};

std::uintmax_t safe_file_size(const std::filesystem::path& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  return ec ? 0 : size;
}

bool zano_wallet_file_is_prepared(std::uintmax_t size) {
  return size >= 4096;
}
#endif

std::string base64_encode(const Bytes& data) {
  static constexpr char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (size_t i = 0; i < data.size(); i += 3) {
    const size_t remaining = data.size() - i;
    const uint32_t a = data[i];
    const uint32_t b = remaining > 1 ? data[i + 1] : 0;
    const uint32_t c = remaining > 2 ? data[i + 2] : 0;
    const uint32_t triple = (a << 16U) | (b << 8U) | c;
    out.push_back(alphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(alphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(remaining > 1 ? alphabet[(triple >> 6U) & 0x3fU] : '=');
    out.push_back(remaining > 2 ? alphabet[triple & 0x3fU] : '=');
  }
  return out;
}

std::optional<Bytes> base64_decode(const std::string& text) {
  auto value_of = [](char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+' || ch == '-') return 62;
    if (ch == '/' || ch == '_') return 63;
    return -1;
  };

  Bytes out;
  int bits = 0;
  int bit_count = 0;
  for (const auto ch : text) {
    if (ch == '=') break;
    if (std::isspace(static_cast<unsigned char>(ch))) continue;
    const auto value = value_of(ch);
    if (value < 0) return std::nullopt;
    bits = (bits << 6) | value;
    bit_count += 6;
    if (bit_count >= 8) {
      bit_count -= 8;
      out.push_back(static_cast<uint8_t>((bits >> bit_count) & 0xff));
    }
  }
  return out;
}

#ifndef _WIN32
bool read_file_bytes(const std::filesystem::path& path, Bytes& out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return false;
  out.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  return true;
}

bool write_file_bytes(const std::filesystem::path& path, const Bytes& bytes) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) return false;
  file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(file);
}

size_t count_token(const Bytes& bytes, const std::string& token) {
  if (bytes.empty() || token.empty() || bytes.size() < token.size()) return 0;
  size_t count = 0;
  auto it = bytes.begin();
  while (it != bytes.end()) {
    it = std::search(it, bytes.end(), token.begin(), token.end());
    if (it == bytes.end()) break;
    ++count;
    ++it;
  }
  return count;
}

size_t count_token_in_file(const std::filesystem::path& path, const std::string& token) {
  Bytes bytes;
  if (!read_file_bytes(path, bytes)) return 0;
  return count_token(bytes, token);
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

ZanoWalletFileChoice choose_zano_wallet_file(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& preferred_file_name
) {
  const auto wallets_dir = work_dir / "wallets";
  const auto preferred_path = wallets_dir / preferred_file_name;
  ZanoWalletFileChoice preferred{preferred_file_name, false, 0};

  std::error_code ec;
  bool found_prepared = false;
  if (std::filesystem::exists(preferred_path, ec)) {
    preferred.exists = true;
    preferred.size = safe_file_size(preferred_path);
    found_prepared = zano_wallet_file_is_prepared(preferred.size);
  }

  if (!std::filesystem::exists(wallets_dir, ec)) return preferred;

  ZanoWalletFileChoice best = preferred;
  for (const auto& entry : std::filesystem::directory_iterator(wallets_dir, ec)) {
    if (ec) break;
    std::error_code entry_ec;
    if (!entry.is_regular_file(entry_ec) || entry_ec) continue;
    const auto path = entry.path();
    const auto file_name = path.filename().string();
    if (file_name.rfind("altbase-zano-", 0) != 0 || file_name.find(scope) == std::string::npos || path.extension() != ".zan") {
      continue;
    }

    const auto size = safe_file_size(path);
    if (!zano_wallet_file_is_prepared(size)) continue;
    if (!found_prepared || size > best.size) {
      best = {file_name, true, size};
      found_prepared = true;
    }
  }

  return found_prepared ? best : preferred;
}

bool import_zano_wallet_file_from_cache(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& preferred_file_name,
  const std::map<std::string, std::string>& params
) {
  auto blob = get_param(params, "cachedWalletState");
  if (blob.empty()) blob = get_param(params, "nativeWalletFileBlob");
  if (blob.empty()) return false;

  auto file_name = get_param(params, "cachedWalletName");
  if (file_name.empty()) file_name = get_param(params, "nativeWalletFileName");
  if (!zano_wallet_file_name_is_safe(file_name, scope)) file_name = preferred_file_name;
  if (!zano_wallet_file_name_is_safe(file_name, scope)) return false;

  const auto decoded = base64_decode(blob);
  if (!decoded.has_value() || !zano_wallet_file_is_prepared(decoded->size())) return false;

  const auto wallets_dir = work_dir / "wallets";
  std::filesystem::create_directories(wallets_dir);
  const auto target = wallets_dir / file_name;
  const auto existing_size = safe_file_size(target);
  if (zano_wallet_file_is_prepared(existing_size) && existing_size >= decoded->size()) return false;

  const auto tmp = wallets_dir / (file_name + ".importtmp");
  if (!write_file_bytes(tmp, *decoded)) return false;
  std::error_code ec;
  std::filesystem::rename(tmp, target, ec);
  if (ec) {
    std::filesystem::remove(target, ec);
    ec.clear();
    std::filesystem::rename(tmp, target, ec);
  }
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return false;
  }
  return true;
}

struct ZanoWalletBackup {
  std::string file_name;
  std::string blob;
  std::uintmax_t size = 0;
};

std::optional<ZanoWalletBackup> zano_wallet_backup(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::string& file_name
) {
  if (!zano_wallet_file_name_is_safe(file_name, scope)) return std::nullopt;
  const auto path = work_dir / "wallets" / file_name;
  const auto size = safe_file_size(path);
  if (!zano_wallet_file_is_prepared(size)) return std::nullopt;

  Bytes bytes;
  if (!read_file_bytes(path, bytes) || bytes.empty()) return std::nullopt;
  return ZanoWalletBackup{
    file_name,
    base64_encode(bytes),
    size,
  };
}
#endif

void attach_zano_wallet_backup(
  PrivacyLightWalletResult& result,
  const std::map<std::string, std::string>& params,
  const ZanoSession& session
) {
#ifdef _WIN32
  try {
    const auto response = zano_module_wallet_state(zano_work_dir(params), session.scope, session.wallet_file_name);
    if (json_has_error(response)) return;
    const auto state = regex_string(response, "stateB64");
    const auto size = regex_number(response, "size");
    const auto file_name = regex_string(response, "fileName");
    if (state.empty() || size.empty() || file_name.empty()) return;
    result.native_wallet_file_name = file_name;
    result.native_wallet_file_blob = state;
    result.native_wallet_file_size = size;
  } catch (...) {
  }
#else
  const auto backup = zano_wallet_backup(zano_work_dir(params), session.scope, session.wallet_file_name);
  if (!backup.has_value()) return;
  result.native_wallet_file_name = backup->file_name;
  result.native_wallet_file_blob = backup->blob;
  result.native_wallet_file_size = std::to_string(backup->size);
#endif
}

#ifdef _WIN32
std::string epic_work_dir(const std::map<std::string, std::string>& params, const std::string& scope) {
  const auto user_data = get_param(params, "userDataDir");
  const auto base = user_data.empty() ? std::string("epic-light") : join_work_dir(user_data, "epic-light");
  return join_work_dir(base, "altbase-epic-v1-" + scope);
}

void attach_epic_wallet_backup(
  PrivacyLightWalletResult& result,
  const std::map<std::string, std::string>& params,
  const std::string& scope
) {
  (void)result;
  (void)params;
  (void)scope;
}
#else
std::filesystem::path epic_work_dir(const std::map<std::string, std::string>& params, const std::string& scope) {
  const auto user_data = get_param(params, "userDataDir");
  const auto base = user_data.empty() ? std::filesystem::current_path() : std::filesystem::path(user_data);
  return base / "epic-light" / ("altbase-epic-v1-" + scope);
}

bool epic_archive_path_is_safe(const std::string& key) {
  if (key.empty()) return false;
  if (key[0] == '/' || key[0] == '\\') return false;
  if (key.find('\\') != std::string::npos || key.find(':') != std::string::npos) return false;
  if (key == "altbase.restore-scan.done") return true;
  if (key.rfind("wallet_data/", 0) != 0) return false;

  size_t start = 0;
  while (start <= key.size()) {
    const auto end = key.find('/', start);
    const auto part = key.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (part.empty() || part == "." || part == "..") return false;
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return true;
}

std::optional<std::string> epic_relative_key(
  const std::filesystem::path& root,
  const std::filesystem::path& file
) {
  std::error_code ec;
  const auto rel = std::filesystem::relative(file, root, ec);
  if (ec) return std::nullopt;
  auto key = rel.generic_string();
  if (!epic_archive_path_is_safe(key)) return std::nullopt;
  return key;
}

std::vector<std::filesystem::path> epic_wallet_backup_paths(const std::filesystem::path& work_dir) {
  std::vector<std::filesystem::path> paths;
  const auto wallet_data = work_dir / "wallet_data";
  paths.push_back(work_dir / "altbase.restore-scan.done");
  paths.push_back(wallet_seed_path(wallet_data));
  paths.push_back(wallet_data / "db" / "sqlite" / "epic.db");
  paths.push_back(wallet_data / "db" / "sqlite" / "epic.db-wal");
  paths.push_back(wallet_data / "db" / "sqlite" / "epic.db-shm");

  const auto saved_txs = wallet_data / "saved_txs";
  std::error_code ec;
  if (std::filesystem::exists(saved_txs, ec)) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(saved_txs, ec)) {
      if (ec) break;
      std::error_code entry_ec;
      if (!entry.is_regular_file(entry_ec) || entry_ec) continue;
      paths.push_back(entry.path());
    }
  }
  return paths;
}

std::uintmax_t epic_wallet_backup_local_size(const std::filesystem::path& work_dir) {
  std::uintmax_t total = 0;
  for (const auto& path : epic_wallet_backup_paths(work_dir)) {
    total += safe_file_size(path);
  }
  return total;
}

bool epic_wallet_data_is_prepared(const std::filesystem::path& work_dir) {
  return safe_file_size(wallet_seed_path(work_dir / "wallet_data")) > 0
    && safe_file_size(work_dir / "wallet_data" / "db" / "sqlite" / "epic.db") >= 4096;
}

struct EpicWalletBackup {
  std::string file_name;
  std::string blob;
  std::uintmax_t size = 0;
};

std::optional<EpicWalletBackup> epic_wallet_backup(
  const std::filesystem::path& work_dir,
  const std::string& scope
) {
  if (!epic_wallet_data_is_prepared(work_dir)) return std::nullopt;

  Bytes archive;
  auto append_text = [&archive](const std::string& text) {
    archive.insert(archive.end(), text.begin(), text.end());
  };
  append_text(std::string(EPIC_WALLET_BACKUP_MAGIC) + "\n");

  std::uintmax_t total_size = 0;
  bool has_seed = false;
  bool has_db = false;
  for (const auto& path : epic_wallet_backup_paths(work_dir)) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) continue;
    const auto key = epic_relative_key(work_dir, path);
    if (!key.has_value()) continue;

    const auto size = safe_file_size(path);
    if (size == 0) continue;
    if (total_size + size > EPIC_WALLET_BACKUP_MAX_BYTES) return std::nullopt;

    Bytes bytes;
    if (!read_file_bytes(path, bytes) || bytes.empty()) continue;
    total_size += bytes.size();
    if (*key == wallet_seed_archive_name()) has_seed = true;
    if (*key == "wallet_data/db/sqlite/epic.db") has_db = true;

    append_text("FILE\t" + *key + "\t" + std::to_string(bytes.size()) + "\t" + base64_encode(bytes) + "\n");
  }

  if (!has_seed || !has_db || total_size == 0) return std::nullopt;
  return EpicWalletBackup{
    "altbase-epic-wallet-v1-" + scope + ".archive",
    base64_encode(archive),
    total_size,
  };
}

bool import_epic_wallet_backup_from_cache(
  const std::filesystem::path& work_dir,
  const std::string& scope,
  const std::map<std::string, std::string>& params
) {
  (void)scope;
  const auto blob = get_param(params, "nativeWalletFileBlob");
  if (blob.empty()) return false;

  const auto decoded = base64_decode(blob);
  if (!decoded.has_value() || decoded->empty()) return false;
  const std::string archive(decoded->begin(), decoded->end());
  std::istringstream input(archive);
  std::string magic;
  if (!std::getline(input, magic) || magic != EPIC_WALLET_BACKUP_MAGIC) return false;

  struct ArchivedFile {
    std::string key;
    Bytes bytes;
  };
  std::vector<ArchivedFile> files;
  std::uintmax_t total_size = 0;
  bool has_seed = false;
  bool has_db = false;
  size_t archived_sent_count = 0;
  std::optional<std::uintmax_t> archived_scanned_height;
  auto parse_archive_size = [](const std::string& text) -> std::optional<std::uintmax_t> {
    if (text.empty()) return std::nullopt;
    if (!std::all_of(text.begin(), text.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
      return std::nullopt;
    }
    try {
      return static_cast<std::uintmax_t>(std::stoull(text));
    } catch (...) {
      return std::nullopt;
    }
  };
  auto parse_marker_height = [](const std::string& text, const std::string& key) -> std::optional<std::uintmax_t> {
    const auto prefix = key + "=";
    size_t start = 0;
    while (start <= text.size()) {
      const auto end = text.find('\n', start);
      auto line = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (line.rfind(prefix, 0) == 0) {
        const auto value = line.substr(prefix.size());
        if (value.empty() || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
          return std::isdigit(ch) != 0;
        })) return std::nullopt;
        try {
          return static_cast<std::uintmax_t>(std::stoull(value));
        } catch (...) {
          return std::nullopt;
        }
      }
      if (end == std::string::npos) break;
      start = end + 1;
    }
    return std::nullopt;
  };
  auto read_local_marker_height = [&parse_marker_height](const std::filesystem::path& marker) -> std::optional<std::uintmax_t> {
    std::ifstream input(marker, std::ios::binary);
    if (!input) return std::nullopt;
    const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return parse_marker_height(text, "scannedHeight");
  };
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    const auto first = line.find('\t');
    const auto second = first == std::string::npos ? std::string::npos : line.find('\t', first + 1);
    const auto third = second == std::string::npos ? std::string::npos : line.find('\t', second + 1);
    if (first == std::string::npos || second == std::string::npos || third == std::string::npos) return false;
    if (line.substr(0, first) != "FILE") return false;

    const auto key = line.substr(first + 1, second - first - 1);
    if (!epic_archive_path_is_safe(key)) return false;
    const auto size_text = line.substr(second + 1, third - second - 1);
    const auto expected_size = parse_archive_size(size_text);
    if (!expected_size.has_value()) return false;
    const auto bytes = base64_decode(line.substr(third + 1));
    if (!bytes.has_value() || bytes->size() != *expected_size) return false;
    if (total_size + bytes->size() > EPIC_WALLET_BACKUP_MAX_BYTES) return false;
    total_size += bytes->size();
    if (key == wallet_seed_archive_name()) has_seed = true;
    if (key == "wallet_data/db/sqlite/epic.db") {
      has_db = true;
      archived_sent_count = count_token(*bytes, "\"tx_type\":\"TxSent");
    }
    if (key == "altbase.restore-scan.done") {
      archived_scanned_height = parse_marker_height(std::string(bytes->begin(), bytes->end()), "scannedHeight");
    }
    files.push_back({key, *bytes});
  }
  if (!has_seed || !has_db || files.empty()) return false;

  if (epic_wallet_data_is_prepared(work_dir)) {
    const auto local_scanned_height = read_local_marker_height(work_dir / "altbase.restore-scan.done");
    const auto local_sent_count = count_token_in_file(work_dir / "wallet_data" / "db" / "sqlite" / "epic.db", "\"tx_type\":\"TxSent");
    const auto local_size = epic_wallet_backup_local_size(work_dir);
    if (
      local_sent_count >= archived_sent_count
      &&
      local_scanned_height.has_value()
      && (
        !archived_scanned_height.has_value()
        || *local_scanned_height >= *archived_scanned_height
      )
      && local_size >= total_size
    ) {
      return false;
    }
  }

  std::filesystem::create_directories(work_dir);
  for (const auto& file : files) {
    const auto target = work_dir / std::filesystem::path(file.key);
    std::filesystem::create_directories(target.parent_path());
    const auto tmp = target.string() + ".importtmp";
    if (!write_file_bytes(tmp, file.bytes)) return false;
    std::error_code ec;
    std::filesystem::rename(tmp, target, ec);
    if (ec) {
      std::filesystem::remove(target, ec);
      ec.clear();
      std::filesystem::rename(tmp, target, ec);
    }
    if (ec) {
      std::filesystem::remove(tmp, ec);
      return false;
    }
  }
  return true;
}

void attach_epic_wallet_backup(
  PrivacyLightWalletResult& result,
  const std::map<std::string, std::string>& params,
  const std::string& scope
) {
  const auto backup = epic_wallet_backup(epic_work_dir(params, scope), scope);
  if (!backup.has_value()) return;
  result.native_wallet_file_name = backup->file_name;
  result.native_wallet_file_blob = backup->blob;
  result.native_wallet_file_size = std::to_string(backup->size);
}
#endif

std::string epic_node_url(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "epicNodeUrl");
  return configured.empty() ? "https://api.altbase.io" : configured;
}

bool is_decimal_number(const std::string& value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return std::isdigit(ch) != 0;
  });
}

uint64_t zano_restore_timestamp(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "restoreTimestamp");
  if (is_decimal_number(configured)) return std::stoull(configured);
  const auto now = static_cast<uint64_t>(std::time(nullptr));
  return now > ZANO_RESTORE_LOOKBACK_SECONDS
    ? now - ZANO_RESTORE_LOOKBACK_SECONDS
    : 0ULL;
}

uint64_t zano_restore_height(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "restoreStartHeight");
  if (!is_decimal_number(configured)) return 0;
  return std::stoull(configured);
}

std::string zano_restore_tag(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "restoreTimestamp");
  return is_decimal_number(configured) ? configured : "recent";
}

bool zano_prepared_wallet_available(
  const std::map<std::string, std::string>& params,
  const PrivacyWalletSecretResult& secret
) {
#ifdef _WIN32
  (void)params;
  (void)secret;
  return false;
#else
  const auto restore_height = zano_restore_height(params);
  const auto restore_tag = zano_restore_tag(params);
  const auto restore_height_tag = restore_height > 0 ? std::to_string(restore_height) : "auto";
  const auto preferred_file_name = "altbase-zano-v8-" + secret.scope + "-h" + restore_height_tag + "-t" + restore_tag + ".zan";
  const auto work_dir = zano_work_dir(params);
  std::filesystem::create_directories(work_dir);

  auto wallet_choice = choose_zano_wallet_file(work_dir, secret.scope, preferred_file_name);
  if (import_zano_wallet_file_from_cache(work_dir, secret.scope, preferred_file_name, params)) {
    wallet_choice = choose_zano_wallet_file(work_dir, secret.scope, preferred_file_name);
  }
  return zano_wallet_file_is_prepared(wallet_choice.size);
#endif
}

uint64_t zano_expected_spendable_units(const std::map<std::string, std::string>& params) {
  const auto expected = get_param(params, "expectedSpendable");
  if (expected.empty()) return 0;
  try {
    return parse_decimal_units(expected, ZANO_ATOMIC_UNITS);
  } catch (...) {
    return 0;
  }
}

std::string zano_node_host(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "zanoNodeHost");
  return configured.empty() ? "https://api.altbase.io" : configured;
}

std::string zano_node_port(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "zanoNodePort");
  return configured.empty() ? "443" : configured;
}

int zano_log_level(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "zanoLogLevel");
  if (!is_decimal_number(configured)) return 0;
  return std::clamp(std::stoi(configured), 0, 4);
}

std::string zano_module_init(
  const std::string& host,
  const std::string& port,
  const std::string& work_dir,
  int log_level
) {
  std::ostringstream request;
  request << "{\"op\":\"init\","
          << "\"host\":\"" << json_escape(host) << "\","
          << "\"port\":\"" << json_escape(port) << "\","
          << "\"workDir\":\"" << json_escape(work_dir) << "\","
          << "\"logLevel\":" << log_level << "}";
  return call_zano_core(request.str());
}

std::string zano_module_reset() {
  return call_zano_core("{\"op\":\"reset\"}");
}

std::string zano_module_open(
  const std::string& file_name,
  const std::string& password
) {
  std::ostringstream request;
  request << "{\"op\":\"open\","
          << "\"fileName\":\"" << json_escape(file_name) << "\","
          << "\"password\":\"" << json_escape(password) << "\"}";
  return call_zano_core(request.str());
}

std::string zano_module_restore(
  const std::string& file_name,
  const std::string& password,
  const std::string& secret_derivation,
  uint64_t restore_from,
  uint64_t restore_height
) {
  const Bytes secret_derivation_bytes(secret_derivation.begin(), secret_derivation.end());
  std::ostringstream request;
  request << "{\"op\":\"restore\","
          << "\"fileName\":\"" << json_escape(file_name) << "\","
          << "\"password\":\"" << json_escape(password) << "\","
          << "\"secretDerivationB64\":\"" << base64_encode(secret_derivation_bytes) << "\","
          << "\"restoreFrom\":" << restore_from << ","
          << "\"restoreHeight\":" << restore_height << "}";
  return call_zano_core(request.str());
}

std::string zano_module_open_or_restore(
  const std::string& work_dir,
  const std::string& scope,
  const std::string& preferred_file_name,
  const std::string& cached_wallet_state,
  const std::string& password,
  const std::string& secret_derivation,
  uint64_t restore_from,
  uint64_t restore_height
) {
  const Bytes secret_derivation_bytes(secret_derivation.begin(), secret_derivation.end());
  std::ostringstream request;
  request << "{\"op\":\"openOrRestore\","
          << "\"workDir\":\"" << json_escape(work_dir) << "\","
          << "\"scope\":\"" << json_escape(scope) << "\","
          << "\"preferredFileName\":\"" << json_escape(preferred_file_name) << "\","
          << "\"cachedStateB64\":\"" << json_escape(cached_wallet_state) << "\","
          << "\"password\":\"" << json_escape(password) << "\","
          << "\"secretDerivationB64\":\"" << base64_encode(secret_derivation_bytes) << "\","
          << "\"restoreFrom\":" << restore_from << ","
          << "\"restoreHeight\":" << restore_height << "}";
  return call_zano_core(request.str());
}

std::string zano_module_wallet_state(
  const std::string& work_dir,
  const std::string& scope,
  const std::string& file_name
) {
  std::ostringstream request;
  request << "{\"op\":\"walletState\","
          << "\"workDir\":\"" << json_escape(work_dir) << "\","
          << "\"scope\":\"" << json_escape(scope) << "\","
          << "\"fileName\":\"" << json_escape(file_name) << "\"}";
  return call_zano_core(request.str());
}

std::string zano_module_sync_call(
  const std::string& method,
  ZanoWalletHandle wallet_id,
  const std::string& params_json
) {
  std::ostringstream request;
  request << "{\"op\":\"syncCall\","
          << "\"method\":\"" << json_escape(method) << "\","
          << "\"walletId\":" << wallet_id << ","
          << "\"params\":" << params_json << "}";
  return call_zano_core(request.str());
}

std::string zano_module_invoke(
  ZanoWalletHandle wallet_id,
  const std::string& request_json
) {
  std::ostringstream request;
  request << "{\"op\":\"invoke\","
          << "\"walletId\":" << wallet_id << ","
          << "\"request\":" << request_json << "}";
  return call_zano_core(request.str());
}

std::string zano_wallet_rpc(
  ZanoWalletHandle wallet_id,
  const std::string& method,
  const std::string& params_json,
  int busy_attempts = 90
) {
  std::ostringstream rpc;
  rpc << "{\"jsonrpc\":\"2.0\",\"id\":\"altbase\",\"method\":\"" << method << "\",\"params\":" << params_json << "}";
  std::string response;
  for (int attempt = 0; attempt < std::max(1, busy_attempts); ++attempt) {
    response = zano_module_invoke(wallet_id, rpc.str());
    if (!json_has_error(response)) return response;
    if (json_error_message(response).find("BUSY") == std::string::npos) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  if (json_has_error(response)) throw std::runtime_error(json_error_message(response));
  return response;
}

ZanoWalletHandle zano_parse_wallet_id(const std::string& response) {
  if (json_has_error(response)) throw std::runtime_error(json_error_message(response));
  const auto wallet_id = regex_number(response, "wallet_id");
  if (wallet_id.empty()) throw std::runtime_error("Zano wallet id was not returned");
  return static_cast<ZanoWalletHandle>(std::stoull(wallet_id));
}

std::string zano_wallet_status(ZanoWalletHandle wallet_id) {
  auto response = zano_module_sync_call("get_wallet_status", wallet_id, "{}");
  if (json_has_error(response)) throw std::runtime_error(json_error_message(response));
  return response;
}

struct ZanoBalance {
  uint64_t balance = 0;
  uint64_t unlocked = 0;
  std::string raw;
};

bool zano_status_ready(const std::string& status) {
  const auto state_text = regex_number(status, "wallet_state");
  const auto daemon_text = regex_number(status, "current_daemon_height");
  const auto wallet_text = regex_number(status, "current_wallet_height");
  if (daemon_text.empty() || wallet_text.empty()) return state_text == "2";
  const auto daemon_height = std::stoull(daemon_text);
  const auto wallet_height = std::stoull(wallet_text);
  return state_text == "2" || (daemon_height > 0 && wallet_height + 2 >= daemon_height);
}

void set_zano_wallet_height(PrivacyLightWalletResult& result, const std::string& status) {
  const auto wallet_text = regex_number(status, "current_wallet_height");
  if (!wallet_text.empty()) result.last_scanned_height = wallet_text;
}

void emit_privacy_sync_progress(
  const std::map<std::string, std::string>& params,
  const std::string& coin,
  uint64_t current_height,
  uint64_t tip_height
);

bool zano_wallet_has_spendable_balance(ZanoWalletHandle wallet_id, int busy_attempts = 1) {
  try {
    const auto response = zano_wallet_rpc(wallet_id, "getbalance", "{}", busy_attempts);
    const auto unlocked_text = regex_number(response, "unlocked_balance");
    const auto unlocked = unlocked_text.empty() ? 0ULL : std::stoull(unlocked_text);
    return unlocked > 0;
  } catch (...) {
    return false;
  }
}

ZanoBalance zano_wallet_balance(ZanoWalletHandle wallet_id, int busy_attempts = 1) {
  ZanoBalance balance;
  balance.raw = zano_wallet_rpc(wallet_id, "getbalance", "{}", busy_attempts);
  const auto balance_text = regex_number(balance.raw, "balance");
  const auto unlocked_text = regex_number(balance.raw, "unlocked_balance");
  balance.balance = balance_text.empty() ? 0ULL : std::stoull(balance_text);
  balance.unlocked = unlocked_text.empty() ? balance.balance : std::stoull(unlocked_text);
  return balance;
}

void ensure_zano_wallet_running(ZanoSession& session) {
  if (session.run_requested || session.wallet_id == 0) return;
  (void)zano_module_sync_call("run_wallet", session.wallet_id, "{}");
  session.run_requested = true;
}

void wait_for_zano_initial_sync(
  ZanoSession& session,
  int attempts = ZANO_INITIAL_SYNC_ATTEMPTS,
  const std::map<std::string, std::string>* params = nullptr
) {
  if (!session.initial_sync_pending || session.wallet_id == 0) return;

  uint64_t last_stored_height = 0;
  for (int attempt = 0; attempt < attempts; ++attempt) {
    try {
      const auto status = zano_wallet_status(session.wallet_id);
      const auto daemon_text = regex_number(status, "current_daemon_height");
      const auto wallet_text = regex_number(status, "current_wallet_height");
      if (params && !daemon_text.empty() && !wallet_text.empty()) {
        const auto wallet_height = std::stoull(wallet_text);
        emit_privacy_sync_progress(*params, "zano", wallet_height, std::stoull(daemon_text));
        if (attempt > 0 && attempt % 20 == 0 && wallet_height > last_stored_height + 500) {
          try {
            (void)zano_wallet_rpc(session.wallet_id, "store", "{}", 1);
            last_stored_height = wallet_height;
          } catch (...) {
          }
        }
      }
      if (zano_status_ready(status)) {
        session.initial_sync_pending = false;
        try {
          (void)zano_wallet_rpc(session.wallet_id, "store", "{}", 5);
        } catch (...) {
        }
        return;
      }
    } catch (...) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(ZANO_INITIAL_SYNC_SLEEP_MS));
  }
}

ZanoSession& ensure_zano_wallet(
  const std::map<std::string, std::string>& params,
  const std::string& mnemonic,
  const PrivacyWalletSecretResult& secret
) {
  const auto address = zano_address_from_mnemonic(mnemonic);
  const auto restore_from = zano_restore_timestamp(params);
  const auto restore_height = zano_restore_height(params);
  const auto restore_tag = zano_restore_tag(params);
  const auto force_rescan = get_param(params, "forceRescan") == "true";
  if (zano_session.initialized && zano_session.scope == secret.scope && zano_session.address == address) {
    if (force_rescan && ((restore_height > 0 && zano_session.restore_height != restore_height) || zano_session.restore_timestamp > restore_from)) {
      (void)zano_module_reset();
      zano_session = {};
    } else {
      ensure_zano_wallet_running(zano_session);
      try {
        zano_session.initial_sync_pending = !zano_status_ready(zano_wallet_status(zano_session.wallet_id));
      } catch (...) {
        zano_session.initial_sync_pending = true;
      }
      return zano_session;
    }
  }
  if (zano_session.initialized) {
    (void)zano_module_reset();
    zano_session = {};
  }

  const auto work_dir = zano_work_dir(params);
#ifdef _WIN32
  const auto init_response = zano_module_init(zano_node_host(params), zano_node_port(params), work_dir, zano_log_level(params));
#else
  std::filesystem::create_directories(work_dir);
  const auto init_response = zano_module_init(zano_node_host(params), zano_node_port(params), work_dir.string(), zano_log_level(params));
#endif
  if (init_response.find("ALREADY_EXISTS") == std::string::npos && json_has_error(init_response)) {
    throw std::runtime_error(json_error_message(init_response));
  }

  const auto restore_height_tag = restore_height > 0 ? std::to_string(restore_height) : "auto";
  const auto generated_file_name = "altbase-zano-v8-" + secret.scope + "-h" + restore_height_tag + "-t" + restore_tag + ".zan";
  const auto cached_wallet_name = get_param(params, "cachedWalletName");
  const auto preferred_file_name = cached_wallet_name.empty() ? generated_file_name : cached_wallet_name;
#ifdef _WIN32
  const auto file_name = preferred_file_name;
  const auto secret_derivation = zano_secret_derivation_from_mnemonic(mnemonic);
  auto open_response = zano_module_open_or_restore(
    work_dir,
    secret.scope,
    preferred_file_name,
    get_param(params, "cachedWalletState"),
    secret.engine_password,
    secret_derivation,
    restore_from,
    restore_height
  );
  const auto selected_file_name = regex_string(open_response, "fileName");
  const auto wallet_exists = regex_bool(open_response, "walletExists");
#else
  auto wallet_choice = choose_zano_wallet_file(work_dir, secret.scope, preferred_file_name);
  if (import_zano_wallet_file_from_cache(work_dir, secret.scope, preferred_file_name, params)) {
    wallet_choice = choose_zano_wallet_file(work_dir, secret.scope, preferred_file_name);
  }
  if (wallet_choice.exists && !zano_wallet_file_is_prepared(wallet_choice.size)) {
    std::error_code remove_error;
    std::filesystem::remove(work_dir / "wallets" / wallet_choice.file_name, remove_error);
    wallet_choice.exists = false;
    wallet_choice.size = 0;
  }
  const auto file_name = wallet_choice.file_name;
  const auto wallet_exists = wallet_choice.exists;
  std::string open_response;
  if (wallet_exists) {
    open_response = zano_module_open(file_name, secret.engine_password);
  } else {
    const auto secret_derivation = zano_secret_derivation_from_mnemonic(mnemonic);
    open_response = zano_module_restore(file_name, secret.engine_password, secret_derivation, restore_from, restore_height);
  }
#endif

  if (json_has_error(open_response)) {
    throw std::runtime_error(json_error_message(open_response));
  }

  zano_session.initialized = true;
  zano_session.scope = secret.scope;
  zano_session.restore_tag = restore_tag;
  zano_session.restore_timestamp = restore_from;
  zano_session.restore_height = restore_height;
  zano_session.wallet_id = zano_parse_wallet_id(open_response);
  zano_session.address = address;
#ifdef _WIN32
  zano_session.wallet_file_name = selected_file_name.empty() ? file_name : selected_file_name;
#else
  zano_session.wallet_file_name = file_name;
#endif
  zano_session.initial_sync_pending = !wallet_exists;
  ensure_zano_wallet_running(zano_session);
  try {
    zano_session.initial_sync_pending = !zano_status_ready(zano_wallet_status(zano_session.wallet_id));
  } catch (...) {
    zano_session.initial_sync_pending = true;
  }
  return zano_session;
}

PrivacyLightWalletResult not_ready(const std::string& code, const std::string& error) {
  return {
    false,
    code,
    error,
    "",
    "0",
    "0",
    "",
    "",
    "[]",
    "",
  };
}

bool populate_zano_balance_result(
  PrivacyLightWalletResult& result,
  ZanoWalletHandle wallet_id,
  int busy_attempts,
  uint64_t* unlocked_out = nullptr,
  std::string* raw_out = nullptr
) {
  if (unlocked_out) *unlocked_out = 0;
  if (raw_out) raw_out->clear();
  try {
    const auto balance = zano_wallet_balance(wallet_id, busy_attempts);
    result.balance = units_to_decimal(balance.balance, ZANO_ATOMIC_UNITS);
    result.spendable = units_to_decimal(balance.unlocked, ZANO_ATOMIC_UNITS);
    if (unlocked_out) *unlocked_out = balance.unlocked;
    if (raw_out) *raw_out = balance.raw;
    return true;
  } catch (const std::exception& error) {
    if (raw_out) *raw_out = std::string("getbalance error: ") + error.what();
    return false;
  } catch (...) {
    if (raw_out) *raw_out = "getbalance error: unknown";
    return false;
  }
}

std::string privacy_api_base(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "apiBaseUrl");
  if (!configured.empty()) return configured;
  return "https://api.altbase.io/api/v1";
}

std::string privacy_raw_base(const std::map<std::string, std::string>& params) {
  auto base = privacy_api_base(params);
  while (!base.empty() && base.back() == '/') base.pop_back();
  constexpr const char* suffix = "/api/v1";
  if (base.size() >= std::strlen(suffix) && base.compare(base.size() - std::strlen(suffix), std::strlen(suffix), suffix) == 0) {
    base.resize(base.size() - std::strlen(suffix));
  }
  return base.empty() ? "https://api.altbase.io" : base;
}

std::string scan_info(const std::map<std::string, std::string>& params, const std::string& coin) {
  try {
    const auto response = http_get(privacy_api_base(params) + "/" + coin + "/privacy/scan-info", 10000);
    if (response.status < 200 || response.status >= 300) return "server scan-info HTTP " + std::to_string(response.status);
    return response.body;
  } catch (const std::exception& e) {
    return std::string("server scan-info unavailable: ") + e.what();
  }
}

int hex_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

template <typename T>
bool pod_from_hex(const std::string& value, T& out) {
  if (value.size() != sizeof(T) * 2) return false;
  std::array<uint8_t, sizeof(T)> bytes{};
  for (size_t i = 0; i < bytes.size(); ++i) {
    const int high = hex_value(value[i * 2]);
    const int low = hex_value(value[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    bytes[i] = static_cast<uint8_t>((high << 4) | low);
  }
  std::memcpy(&out, bytes.data(), bytes.size());
  return true;
}

template <typename T>
std::string pod_to_hex_bytes(const T& value) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
  std::ostringstream out;
  constexpr char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(T); ++i) {
    out << hex[(bytes[i] >> 4U) & 0x0fU] << hex[bytes[i] & 0x0fU];
  }
  return out.str();
}

std::optional<std::string> json_array_content(const std::string& json, const std::string& key) {
  const auto key_pos = json.find("\"" + key + "\"");
  if (key_pos == std::string::npos) return std::nullopt;
  const auto open = json.find('[', key_pos);
  if (open == std::string::npos) return std::nullopt;

  bool in_string = false;
  bool escaped = false;
  int depth = 0;
  const size_t content_start = open + 1;
  for (size_t i = open; i < json.size(); ++i) {
    const char ch = json[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }
    if (ch == '"') {
      in_string = true;
      continue;
    }
    if (ch == '[') {
      ++depth;
    } else if (ch == ']') {
      --depth;
      if (depth == 0) return json.substr(content_start, i - content_start);
    }
  }
  return std::nullopt;
}

std::vector<std::string> split_json_objects(const std::string& content) {
  std::vector<std::string> objects;
  bool in_string = false;
  bool escaped = false;
  int depth = 0;
  size_t start = std::string::npos;

  for (size_t i = 0; i < content.size(); ++i) {
    const char ch = content[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }
    if (ch == '"') {
      in_string = true;
      continue;
    }
    if (ch == '{') {
      if (depth == 0) start = i;
      ++depth;
    } else if (ch == '}') {
      --depth;
      if (depth == 0 && start != std::string::npos) {
        objects.push_back(content.substr(start, i - start + 1));
        start = std::string::npos;
      }
    }
  }
  return objects;
}

std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
  std::vector<std::string> values;
  const auto content = json_array_content(json, key);
  if (!content) return values;

  bool in_string = false;
  bool escaped = false;
  std::string value;
  for (const char ch : *content) {
    if (!in_string) {
      if (ch == '"') {
        in_string = true;
        value.clear();
      }
      continue;
    }
    if (escaped) {
      value.push_back(ch);
      escaped = false;
      continue;
    }
    if (ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == '"') {
      values.push_back(value);
      in_string = false;
      continue;
    }
    value.push_back(ch);
  }
  return values;
}

struct ZanoCompactOutput {
  uint64_t height = 0;
  uint64_t timestamp = 0;
  uint64_t output_index = 0;
  uint64_t amount_atomic = 0;
  uint64_t fee_atomic = 0;
  bool spent = false;
  std::string type;
  std::string tx_id;
  std::string tx_pub_key;
  std::vector<std::string> derivation_hints;
  std::vector<std::string> keys;
};

struct ZanoCompactTxHeader {
  std::string tx_id;
  std::string tx_pub_key;
  std::vector<std::string> derivation_hints;
};

uint64_t parse_u64_or_zero(const std::string& value) {
  if (value.empty()) return 0;
  try {
    return std::stoull(value);
  } catch (...) {
    return 0;
  }
}

uint64_t json_u64_field(const std::string& json, const std::string& key) {
  const auto number = regex_number(json, key);
  if (!number.empty()) return parse_u64_or_zero(number);
  return parse_u64_or_zero(regex_string(json, key));
}

#ifdef _WIN32
uint64_t epic_progress_start_height(
  const std::map<std::string, std::string>& params,
  const std::string& scope,
  uint64_t restore_start_height,
  uint64_t tip_height
) {
  (void)params;
  (void)scope;
  (void)tip_height;
  return restore_start_height;
}
#else
std::optional<uint64_t> epic_restore_marker_height(const std::filesystem::path& marker, const std::string& key) {
  std::ifstream input(marker);
  if (!input) return std::nullopt;
  const auto prefix = key + "=";
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind(prefix, 0) != 0) continue;
    const auto value = line.substr(prefix.size());
    if (!is_decimal_number(value)) return std::nullopt;
    return parse_u64_or_zero(value);
  }
  return std::nullopt;
}

uint64_t epic_progress_start_height(
  const std::map<std::string, std::string>& params,
  const std::string& scope,
  uint64_t restore_start_height,
  uint64_t tip_height
) {
  const auto marker = epic_work_dir(params, scope) / "altbase.restore-scan.done";
  const auto scanned_height = epic_restore_marker_height(marker, "scannedHeight");
  if (!scanned_height.has_value() || *scanned_height <= restore_start_height) return restore_start_height;

  const auto capped_scanned_height = std::min(*scanned_height, tip_height);
  if (capped_scanned_height <= EPIC_RECENT_RESCAN_BLOCKS) return restore_start_height;
  return std::max(restore_start_height, capped_scanned_height - EPIC_RECENT_RESCAN_BLOCKS);
}
#endif

std::vector<ZanoCompactOutput> parse_zano_compact_outputs(const std::string& json) {
  std::vector<ZanoCompactOutput> outputs;
  const auto content = json_array_content(json, "outputs");
  if (!content) return outputs;

  for (const auto& object : split_json_objects(*content)) {
    ZanoCompactOutput output;
    output.height = json_u64_field(object, "height");
    output.timestamp = json_u64_field(object, "timestamp");
    output.output_index = json_u64_field(object, "outputIndex");
    output.amount_atomic = json_u64_field(object, "amountAtomic");
    output.fee_atomic = json_u64_field(object, "feeAtomic");
    output.spent = regex_bool(object, "isSpent");
    output.type = regex_string(object, "type");
    output.tx_id = regex_string(object, "txId");
    output.tx_pub_key = regex_string(object, "txPubKey");
    output.derivation_hints = json_string_array_field(object, "derivationHints");
    output.keys = json_string_array_field(object, "keys");
    if (!output.type.empty() && !output.tx_id.empty() && !output.tx_pub_key.empty()) {
      outputs.push_back(std::move(output));
    }
  }
  return outputs;
}

std::vector<ZanoCompactTxHeader> parse_zano_compact_transactions(const std::string& json) {
  std::vector<ZanoCompactTxHeader> transactions;
  for (const auto& compact : json_string_array_field(json, "transactionsCompact")) {
    const auto first = compact.find('|');
    const auto second = first == std::string::npos ? std::string::npos : compact.find('|', first + 1);
    if (first == std::string::npos || second == std::string::npos) continue;

    ZanoCompactTxHeader tx;
    tx.tx_id = compact.substr(0, first);
    tx.tx_pub_key = compact.substr(first + 1, second - first - 1);
    std::string hint;
    for (size_t i = second + 1; i <= compact.size(); ++i) {
      if (i == compact.size() || compact[i] == ',') {
        if (!hint.empty()) tx.derivation_hints.push_back(hint);
        hint.clear();
      } else {
        hint.push_back(compact[i]);
      }
    }
    if (!tx.tx_id.empty() && !tx.tx_pub_key.empty()) transactions.push_back(std::move(tx));
  }
  if (!transactions.empty()) return transactions;

  const auto content = json_array_content(json, "transactions");
  if (!content) return transactions;

  for (const auto& object : split_json_objects(*content)) {
    ZanoCompactTxHeader tx;
    tx.tx_id = regex_string(object, "txId");
    tx.tx_pub_key = regex_string(object, "txPubKey");
    tx.derivation_hints = json_string_array_field(object, "derivationHints");
    if (!tx.tx_id.empty() && !tx.tx_pub_key.empty()) transactions.push_back(std::move(tx));
  }
  return transactions;
}

#ifndef _WIN32
std::string hex_from_bytes(const std::string& bytes) {
  std::ostringstream out;
  constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char byte : bytes) {
    out << hex[(byte >> 4U) & 0x0fU] << hex[byte & 0x0fU];
  }
  return out.str();
}

bool zano_derivation_hint_matches(const std::vector<std::string>& hints, const crypto::key_derivation& derivation) {
  if (hints.empty()) return true;
  const auto hint = currency::make_tx_derivation_hint_from_uint16(currency::get_derivation_hint(derivation));
  const auto expected = hex_from_bytes(hint.msg);
  return std::find(hints.begin(), hints.end(), expected) != hints.end();
}

bool zano_compact_output_amount(
  const currency::account_keys& keys,
  const ZanoCompactOutput& output,
  uint64_t& decoded_amount
) {
  decoded_amount = 0;
  crypto::public_key tx_pub_key{};
  if (!pod_from_hex(output.tx_pub_key, tx_pub_key)) return false;

  crypto::key_derivation derivation{};
  if (!crypto::generate_key_derivation(tx_pub_key, keys.view_secret_key, derivation)) return false;
  if (!zano_derivation_hint_matches(output.derivation_hints, derivation)) return false;

  if (output.type == "bare" && !output.keys.empty()) {
    currency::txout_to_key out_key;
    if (!pod_from_hex(output.keys.front(), out_key.key)) return false;
    if (!currency::is_out_to_acc(keys.account_address, out_key, derivation, output.output_index)) return false;
    decoded_amount = output.amount_atomic;
    return true;
  }

  if (output.type != "zarcanum" || output.keys.size() < 5) return false;

  currency::tx_out_zarcanum zc_out;
  uint64_t encrypted_amount = 0;
  if (!pod_from_hex(output.keys[0], zc_out.stealth_address)) return false;
  if (!pod_from_hex(output.keys[1], zc_out.concealing_point)) return false;
  if (!pod_from_hex(output.keys[2], zc_out.amount_commitment)) return false;
  if (!pod_from_hex(output.keys[3], zc_out.blinded_asset_id)) return false;
  if (!pod_from_hex(output.keys[4], encrypted_amount)) return false;
  zc_out.encrypted_amount = encrypted_amount;

  crypto::public_key asset_id{};
  crypto::scalar_t amount_blinding_mask{};
  crypto::scalar_t asset_id_blinding_mask{};
  if (!currency::is_out_to_acc(
        keys.account_address,
        zc_out,
        derivation,
        output.output_index,
        decoded_amount,
        asset_id,
        amount_blinding_mask,
        asset_id_blinding_mask
      )) {
    return false;
  }
  return asset_id == currency::native_coin_asset_id;
}

bool zano_compact_output_key_image(
  const currency::account_keys& keys,
  const ZanoCompactOutput& output,
  std::string& key_image_hex
) {
  crypto::public_key tx_pub_key{};
  if (!pod_from_hex(output.tx_pub_key, tx_pub_key)) return false;

  crypto::public_key out_pub_key{};
  if (output.type == "bare") {
    if (output.keys.empty() || !pod_from_hex(output.keys.front(), out_pub_key)) return false;
  } else if (output.type == "zarcanum") {
    if (output.keys.empty() || !pod_from_hex(output.keys[0], out_pub_key)) return false;
  } else {
    return false;
  }

  currency::keypair in_ephemeral{};
  crypto::key_image key_image{};
  if (!currency::generate_key_image_helper(keys, tx_pub_key, output.output_index, in_ephemeral, key_image)) {
    return false;
  }
  if (!(in_ephemeral.pub == out_pub_key)) return false;

  key_image_hex = pod_to_hex_bytes(key_image);
  return true;
}

bool zano_compact_tx_may_belong_to_wallet(
  const currency::account_keys& keys,
  const ZanoCompactTxHeader& tx
) {
  crypto::public_key tx_pub_key{};
  if (!pod_from_hex(tx.tx_pub_key, tx_pub_key)) return false;
  crypto::key_derivation derivation{};
  if (!crypto::generate_key_derivation(tx_pub_key, keys.view_secret_key, derivation)) return false;
  return zano_derivation_hint_matches(tx.derivation_hints, derivation);
}
#endif

std::string json_string_list(const std::vector<std::string>& values) {
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out << ',';
    out << "\"" << json_escape(values[i]) << "\"";
  }
  out << ']';
  return out.str();
}

void emit_privacy_recovery_progress(
  const std::map<std::string, std::string>& params,
  const std::string& coin,
  uint64_t from_height,
  uint64_t next_height,
  uint64_t tip_height
) {
  const auto request_id = get_param(params, "requestId");
  const auto progress_token = get_param(params, "progressToken");
  if (request_id.empty() || progress_token.empty()) return;

  const uint64_t total = tip_height >= from_height ? tip_height - from_height + 1 : 0;
  uint64_t scanned = 0;
  if (total > 0 && next_height > from_height) scanned = std::min(next_height - from_height, total);
  const uint64_t remaining = total > scanned ? total - scanned : 0;
  const uint64_t current = scanned == 0 ? from_height : from_height + scanned - 1;
  const uint64_t percent = total == 0 ? 100 : std::min<uint64_t>(100, (scanned * 100) / total);

  std::cout << "{\"id\":\"" << json_escape(request_id)
            << "\",\"event\":\"progress\",\"payload\":{"
            << "\"type\":\"privacyRecovery\","
            << "\"progressToken\":\"" << json_escape(progress_token) << "\","
            << "\"coin\":\"" << json_escape(coin) << "\","
            << "\"fromHeight\":" << from_height << ','
            << "\"currentHeight\":" << current << ','
            << "\"tipHeight\":" << tip_height << ','
            << "\"totalBlocks\":" << total << ','
            << "\"scannedBlocks\":" << scanned << ','
            << "\"blocksRemaining\":" << remaining << ','
            << "\"percent\":" << percent
            << "}}" << std::endl;
}

void emit_privacy_sync_progress(
  const std::map<std::string, std::string>& params,
  const std::string& coin,
  uint64_t current_height,
  uint64_t tip_height
) {
  const auto request_id = get_param(params, "requestId");
  const auto progress_token = get_param(params, "progressToken");
  if (request_id.empty() || progress_token.empty()) return;

  const uint64_t scanned = tip_height == 0 ? 0 : std::min(current_height, tip_height);
  const uint64_t remaining = tip_height > scanned ? tip_height - scanned : 0;
  const uint64_t percent = tip_height == 0 ? 100 : std::min<uint64_t>(100, (scanned * 100) / tip_height);

  std::cout << "{\"id\":\"" << json_escape(request_id)
            << "\",\"event\":\"progress\",\"payload\":{"
            << "\"type\":\"privacyRecovery\","
            << "\"progressToken\":\"" << json_escape(progress_token) << "\","
            << "\"coin\":\"" << json_escape(coin) << "\","
            << "\"fromHeight\":0,"
            << "\"currentHeight\":" << current_height << ','
            << "\"tipHeight\":" << tip_height << ','
            << "\"totalBlocks\":" << tip_height << ','
            << "\"scannedBlocks\":" << scanned << ','
            << "\"blocksRemaining\":" << remaining << ','
            << "\"percent\":" << percent
            << "}}" << std::endl;
}

struct ZanoCompactTx {
  uint64_t amount_atomic = 0;
  uint64_t fee_atomic = 0;
  uint64_t height = 0;
  uint64_t timestamp = 0;
  uint64_t spent_height = 0;
  bool has_unspent = false;
  bool has_spent = false;
};

struct ZanoMatchedOutput {
  std::string tx_id;
  std::string key_image;
  uint64_t amount_atomic = 0;
  uint64_t fee_atomic = 0;
  uint64_t height = 0;
  uint64_t timestamp = 0;
  bool spent = false;
  uint64_t spent_height = 0;
};

struct ZanoScanState {
  uint64_t height = 0;
  std::vector<ZanoMatchedOutput> outputs;
};

struct ZanoKeyImageState {
  bool spent = false;
  uint64_t spent_height = 0;
};

struct ZanoSpendTx {
  std::string tx_id;
  uint64_t height = 0;
  uint64_t timestamp = 0;
  uint64_t fee_atomic = 0;
};

struct ZanoOutgoingTx {
  uint64_t spent_atomic = 0;
  uint64_t fee_atomic = 0;
  uint64_t height = 0;
  uint64_t timestamp = 0;
};

bool looks_like_hex(const std::string& value, size_t size) {
  return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return std::isxdigit(ch) != 0;
  });
}

std::string zano_output_cache_key(const ZanoMatchedOutput& output) {
  if (!output.key_image.empty()) return output.tx_id + ":" + output.key_image;
  return output.tx_id + ":" + std::to_string(output.height) + ":" + std::to_string(output.amount_atomic);
}

ZanoScanState parse_zano_scan_state(const std::string& json) {
  ZanoScanState state;
  if (json.empty()) return state;
  const auto version = json_u64_field(json, "version");
  if (version != 1) return state;
  const auto coin = regex_string(json, "coin");
  if (!coin.empty() && coin != "zano") return state;
  state.height = json_u64_field(json, "height");

  const auto content = json_array_content(json, "outputs");
  if (!content) return state;
  std::unordered_set<std::string> seen;
  for (const auto& object : split_json_objects(*content)) {
    ZanoMatchedOutput output;
    output.tx_id = regex_string(object, "txId");
    output.key_image = regex_string(object, "keyImage");
    output.amount_atomic = json_u64_field(object, "amountAtomic");
    output.fee_atomic = json_u64_field(object, "feeAtomic");
    output.height = json_u64_field(object, "height");
    output.timestamp = json_u64_field(object, "timestamp");
    output.spent = regex_bool(object, "spent");
    output.spent_height = json_u64_field(object, "spentHeight");
    if (!looks_like_hex(output.tx_id, 64)) continue;
    if (!looks_like_hex(output.key_image, 64)) continue;
    if (output.amount_atomic == 0 || output.height == 0) continue;
    if (!seen.insert(zano_output_cache_key(output)).second) continue;
    state.outputs.push_back(std::move(output));
  }
  return state;
}

void zano_add_matched_output(
  std::unordered_map<std::string, ZanoCompactTx>& txs,
  std::vector<ZanoMatchedOutput>& matched_outputs,
  std::unordered_set<std::string>& seen_outputs,
  ZanoMatchedOutput output
) {
  if (output.tx_id.empty() || output.amount_atomic == 0) return;
  if (!seen_outputs.insert(zano_output_cache_key(output)).second) return;
  auto& tx = txs[output.tx_id];
  tx.amount_atomic += output.amount_atomic;
  tx.fee_atomic = output.fee_atomic;
  tx.height = tx.height == 0 ? output.height : std::min(tx.height, output.height);
  tx.timestamp = tx.timestamp == 0 ? output.timestamp : std::min(tx.timestamp, output.timestamp);
  matched_outputs.push_back(std::move(output));
}

std::string zano_scan_state_json(uint64_t height, const std::vector<ZanoMatchedOutput>& outputs) {
  std::ostringstream out;
  out << "{\"version\":1,\"coin\":\"zano\",\"height\":" << height << ",\"outputs\":[";
  bool first = true;
  std::unordered_set<std::string> seen;
  for (const auto& output : outputs) {
    if (!looks_like_hex(output.tx_id, 64) || !looks_like_hex(output.key_image, 64)) continue;
    if (output.amount_atomic == 0 || output.height == 0) continue;
    if (!seen.insert(zano_output_cache_key(output)).second) continue;
    if (!first) out << ',';
    first = false;
    out << "{\"txId\":\"" << json_escape(output.tx_id) << "\","
        << "\"keyImage\":\"" << json_escape(output.key_image) << "\","
        << "\"amountAtomic\":" << output.amount_atomic << ','
        << "\"feeAtomic\":" << output.fee_atomic << ','
        << "\"height\":" << output.height << ','
        << "\"timestamp\":" << output.timestamp << ','
        << "\"spent\":" << (output.spent ? "true" : "false") << ','
        << "\"spentHeight\":" << output.spent_height
        << "}";
  }
  out << "]}";
  return out.str();
}

#ifndef _WIN32
std::optional<std::unordered_map<std::string, ZanoKeyImageState>> zano_check_key_images(
  const std::map<std::string, std::string>& params,
  const std::vector<std::string>& key_images
) {
  if (key_images.empty()) return std::unordered_map<std::string, ZanoKeyImageState>{};

  currency::COMMAND_RPC_CHECK_KEYIMAGES::request request{};
  std::vector<std::string> ordered;
  ordered.reserve(key_images.size());
  for (const auto& key_image_hex : key_images) {
    crypto::key_image key_image{};
    if (!pod_from_hex(key_image_hex, key_image)) continue;
    request.images.push_back(key_image);
    ordered.push_back(key_image_hex);
  }
  if (ordered.empty()) return std::unordered_map<std::string, ZanoKeyImageState>{};

  std::string body;
  if (!epee::serialization::store_t_to_binary(request, body)) return std::nullopt;

  try {
    const auto response = http_post_binary(privacy_raw_base(params) + "/check_keyimages.bin", body, 30000);
    if (response.status < 200 || response.status >= 300) return std::nullopt;

    currency::COMMAND_RPC_CHECK_KEYIMAGES::response parsed{};
    if (!epee::serialization::load_t_from_binary(parsed, response.body)) return std::nullopt;

    std::unordered_map<std::string, ZanoKeyImageState> spent_by_key_image;
    auto status_it = parsed.images_stat.begin();
    for (const auto& key_image_hex : ordered) {
      if (status_it == parsed.images_stat.end()) break;
      // Zano returns 0 for unspent key images and the spent block height otherwise.
      spent_by_key_image[key_image_hex] = ZanoKeyImageState{*status_it != 0, *status_it};
      ++status_it;
    }
    return spent_by_key_image;
  } catch (...) {
    return std::nullopt;
  }
}
#endif

std::optional<std::string> zano_json_rpc(
  const std::map<std::string, std::string>& params,
  const std::string& method,
  const std::string& rpc_params,
  long timeout_ms = 30000
) {
  std::ostringstream body;
  body << "{\"jsonrpc\":\"2.0\",\"id\":\"altbase-zano\",\"method\":\""
       << json_escape(method) << "\",\"params\":" << rpc_params << "}";
  try {
    const auto response = http_post_json(privacy_raw_base(params) + "/json_rpc", body.str(), timeout_ms);
    if (response.status < 200 || response.status >= 300) return std::nullopt;
    if (response.body.find("\"error\"") != std::string::npos &&
        response.body.find("\"result\"") == std::string::npos) {
      return std::nullopt;
    }
    return response.body;
  } catch (...) {
    return std::nullopt;
  }
}

std::vector<std::string> zano_tx_ids_at_height(
  const std::map<std::string, std::string>& params,
  uint64_t height
) {
  std::ostringstream rpc_params;
  rpc_params << "{\"height_start\":" << height << ",\"count\":1,\"ignore_transactions\":false}";
  const auto response = zano_json_rpc(params, "get_blocks_details", rpc_params.str(), 30000);
  if (!response) return {};

  const auto content = json_array_content(*response, "transactions_details");
  if (!content) return {};

  std::vector<std::string> ids;
  for (const auto& object : split_json_objects(*content)) {
    const auto tx_id = regex_string(object, "id");
    if (!tx_id.empty()) ids.push_back(tx_id);
  }
  return ids;
}

std::optional<ZanoSpendTx> zano_find_spend_tx(
  const std::map<std::string, std::string>& params,
  uint64_t height,
  const std::string& key_image
) {
  if (height == 0 || key_image.empty()) return std::nullopt;

  const auto ids = zano_tx_ids_at_height(params, height);
  for (const auto& tx_id : ids) {
    std::ostringstream rpc_params;
    rpc_params << "{\"tx_hash\":\"" << json_escape(tx_id) << "\"}";
    const auto response = zano_json_rpc(params, "get_tx_details", rpc_params.str(), 30000);
    if (!response) continue;
    if (response->find(key_image) == std::string::npos) continue;

    ZanoSpendTx tx;
    tx.tx_id = tx_id;
    tx.height = height;
    tx.timestamp = json_u64_field(*response, "timestamp");
    tx.fee_atomic = json_u64_field(*response, "fee");
    return tx;
  }
  return std::nullopt;
}

#ifndef _WIN32
std::optional<PrivacyLightWalletResult> zano_compact_snapshot(
  const std::map<std::string, std::string>& params,
  const std::string& mnemonic,
  const std::string& address
) {
  const auto info = scan_info(params, "zano");
  if (info.find("\"scanModel\":\"compact-light-index-v1\"") == std::string::npos ||
      info.find("\"ready\":true") == std::string::npos) {
    return std::nullopt;
  }

  const auto top_text = regex_number(info, "indexedHeight").empty()
    ? regex_number(info, "blocks")
    : regex_number(info, "indexedHeight");
  if (top_text.empty()) return std::nullopt;
  const uint64_t top_height = parse_u64_or_zero(top_text);

  uint64_t start_height = 0;
  const auto restore_start = get_param(params, "restoreStartHeight");
  if (is_decimal_number(restore_start)) {
    start_height = parse_u64_or_zero(restore_start);
  } else {
    start_height = top_height > 3000 ? top_height - 3000 : 0;
  }
  if (start_height > top_height) start_height = top_height;

  const auto cached_state = parse_zano_scan_state(get_param(params, "scanState"));
  const bool fast_compact = get_param(params, "fastCompact") == "true";
  const bool force_rescan = get_param(params, "forceRescan") == "true";
  const uint64_t restore_start_height = start_height;
  if (!force_rescan && !cached_state.outputs.empty() && cached_state.height > restore_start_height) {
    const uint64_t resume_height = cached_state.height > ZANO_SCAN_STATE_REORG_OVERLAP
      ? cached_state.height - ZANO_SCAN_STATE_REORG_OVERLAP
      : restore_start_height;
    start_height = std::max(restore_start_height, std::min(resume_height, top_height));
  }

  uint64_t chunk_size = parse_u64_or_zero(regex_number(info, "maxBlocksPerChunk"));
  if (chunk_size == 0 || chunk_size > 1000) chunk_size = 1000;

  currency::account_base account;
  if (!account.restore_from_secret_derivation(zano_secret_derivation_from_mnemonic(mnemonic), false, 0)) {
    return std::nullopt;
  }
  const auto& account_keys = account.get_keys();
  emit_privacy_recovery_progress(params, "zano", start_height, start_height, top_height);

  uint64_t balance_atomic = 0;
  std::unordered_map<std::string, ZanoCompactTx> txs;
  std::unordered_map<std::string, ZanoOutgoingTx> outgoing_txs;
  std::vector<ZanoMatchedOutput> matched_outputs;
  std::unordered_set<std::string> seen_outputs;
  if (!force_rescan) {
    for (const auto& cached_output : cached_state.outputs) {
      if (cached_output.height >= start_height) continue;
      zano_add_matched_output(txs, matched_outputs, seen_outputs, cached_output);
    }
  }
  uint64_t cursor = start_height;
  const auto base = privacy_api_base(params);
  while (cursor <= top_height) {
    const uint64_t end = std::min(top_height, cursor + chunk_size - 1);
    std::ostringstream headers_body;
    headers_body << "{\"fromHeight\":" << cursor
                 << ",\"toHeight\":" << end
                 << ",\"headersOnly\":true,\"headersCompact\":true}";
    const auto headers_response = http_post_json(base + "/zano/privacy/scan-chunk", headers_body.str(), 30000);
    if (headers_response.status < 200 || headers_response.status >= 300 ||
        headers_response.body.find("\"scanModel\":\"compact-light-index-v1\"") == std::string::npos ||
        headers_response.body.find("\"ready\":true") == std::string::npos) {
      return std::nullopt;
    }

    std::vector<std::string> candidate_tx_ids;
    for (const auto& tx : parse_zano_compact_transactions(headers_response.body)) {
      if (zano_compact_tx_may_belong_to_wallet(account_keys, tx)) {
        candidate_tx_ids.push_back(tx.tx_id);
      }
    }

    std::string response_body = headers_response.body;
    if (!candidate_tx_ids.empty()) {
      std::ostringstream body;
      body << "{\"fromHeight\":" << cursor
           << ",\"toHeight\":" << end
           << ",\"txIds\":" << json_string_list(candidate_tx_ids)
           << "}";
      const auto response = http_post_json(base + "/zano/privacy/scan-chunk", body.str(), 30000);
      if (response.status < 200 || response.status >= 300 ||
          response.body.find("\"scanModel\":\"compact-light-index-v1\"") == std::string::npos ||
          response.body.find("\"ready\":true") == std::string::npos) {
        return std::nullopt;
      }
      response_body = response.body;
    }

    for (const auto& output : parse_zano_compact_outputs(response_body)) {
      uint64_t amount_atomic = 0;
      if (!zano_compact_output_amount(account_keys, output, amount_atomic)) continue;
      std::string key_image;
      const auto has_key_image = zano_compact_output_key_image(account_keys, output, key_image);
      zano_add_matched_output(txs, matched_outputs, seen_outputs, {
        output.tx_id,
        has_key_image ? key_image : "",
        amount_atomic,
        output.fee_atomic,
        output.height,
        output.timestamp,
        output.spent,
        0
      });
    }

    const auto next_text = regex_number(headers_response.body, "nextHeight");
    const uint64_t next = parse_u64_or_zero(next_text);
    const uint64_t next_cursor = next > cursor ? next : end + 1;
    emit_privacy_recovery_progress(params, "zano", start_height, next_cursor, top_height);
    cursor = next_cursor;
  }

  std::vector<std::string> key_images;
  key_images.reserve(matched_outputs.size());
  for (const auto& output : matched_outputs) {
    if (!output.key_image.empty()) key_images.push_back(output.key_image);
  }
  const auto spent_by_key_image = zano_check_key_images(params, key_images);
  bool all_spend_states_verified = spent_by_key_image.has_value() || key_images.empty();

  for (auto& output : matched_outputs) {
    bool spent = output.spent;
    if (!output.key_image.empty() && spent_by_key_image.has_value()) {
      const auto it = spent_by_key_image->find(output.key_image);
      if (it != spent_by_key_image->end()) {
        spent = it->second.spent;
        output.spent_height = it->second.spent_height;
      } else {
        all_spend_states_verified = false;
      }
    } else if (!output.key_image.empty() && !spent_by_key_image.has_value()) {
      all_spend_states_verified = false;
    }
    output.spent = spent;
    if (!spent) {
      balance_atomic += output.amount_atomic;
      txs[output.tx_id].has_unspent = true;
    } else {
      txs[output.tx_id].has_spent = true;
      txs[output.tx_id].spent_height = output.spent_height;
      if (!fast_compact && output.spent_height > 0) {
        if (const auto spend_tx = zano_find_spend_tx(params, output.spent_height, output.key_image)) {
          auto& outgoing = outgoing_txs[spend_tx->tx_id];
          outgoing.spent_atomic += output.amount_atomic;
          outgoing.fee_atomic = spend_tx->fee_atomic;
          outgoing.height = outgoing.height == 0 ? spend_tx->height : std::min(outgoing.height, spend_tx->height);
          outgoing.timestamp = outgoing.timestamp == 0 ? spend_tx->timestamp : std::min(outgoing.timestamp, spend_tx->timestamp);
        }
      }
    }
  }

  struct ZanoHistoryRow {
    std::string tx_id;
    std::string type;
    uint64_t amount_atomic = 0;
    uint64_t fee_atomic = 0;
    uint64_t height = 0;
    uint64_t timestamp = 0;
    uint64_t spent_height = 0;
    bool spent = false;
  };

  std::vector<ZanoHistoryRow> ordered;
  ordered.reserve(txs.size() + outgoing_txs.size());
  for (const auto& [tx_id, tx] : txs) {
    if (outgoing_txs.find(tx_id) != outgoing_txs.end()) continue;
    ordered.push_back({tx_id, "incoming", tx.amount_atomic, tx.fee_atomic, tx.height, tx.timestamp, tx.spent_height, tx.has_spent && !tx.has_unspent});
  }
  for (const auto& [tx_id, tx] : outgoing_txs) {
    uint64_t change_atomic = 0;
    const auto change_it = txs.find(tx_id);
    if (change_it != txs.end()) change_atomic = change_it->second.amount_atomic;
    uint64_t amount_atomic = tx.spent_atomic;
    if (amount_atomic > change_atomic) amount_atomic -= change_atomic;
    else amount_atomic = 0;
    if (amount_atomic > tx.fee_atomic) amount_atomic -= tx.fee_atomic;
    ordered.push_back({tx_id, "outgoing", amount_atomic, tx.fee_atomic, tx.height, tx.timestamp, 0, false});
  }
  std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
    if (a.timestamp != b.timestamp) return a.timestamp > b.timestamp;
    return a.tx_id < b.tx_id;
  });

  std::ostringstream transactions;
  transactions << '[';
  bool first = true;
  for (const auto& tx : ordered) {
    if (!first) transactions << ',';
    first = false;
    const auto confirmations = top_height >= tx.height ? top_height - tx.height + 1 : 0;
    transactions << "{\"id\":\"" << json_escape(tx.tx_id) << "\","
                 << "\"tx_hash\":\"" << json_escape(tx.tx_id) << "\","
                 << "\"type\":\"" << tx.type << "\","
                 << "\"status\":\"confirmed\","
                 << "\"amount\":\"" << units_to_decimal(tx.amount_atomic, ZANO_ATOMIC_UNITS) << "\","
                 << "\"fee\":\"" << units_to_decimal(tx.fee_atomic, ZANO_ATOMIC_UNITS) << "\","
                 << "\"height\":" << tx.height << ','
                 << "\"timestamp\":" << tx.timestamp << ','
                 << "\"confirmations\":" << confirmations << ','
                 << "\"spent\":" << (tx.spent ? "true" : "false") << ','
                 << "\"spentHeight\":" << tx.spent_height << ','
                 << (tx.type == "outgoing"
                   ? "\"from\":\"" + json_escape(address) + "\""
                   : "\"to\":\"" + json_escape(address) + "\"")
                 << "}";
  }
  transactions << ']';

  PrivacyLightWalletResult result;
  result.ok = true;
  result.code = "zano-compact-scan";
  result.address = address;
  result.balance = units_to_decimal(balance_atomic, ZANO_ATOMIC_UNITS);
  result.spendable = result.balance;
  result.transactions = transactions.str();
  result.last_scanned_height = std::to_string(top_height);
  result.scan_state = zano_scan_state_json(top_height, matched_outputs);
  result.server_status = info;
  if (all_spend_states_verified && !key_images.empty()) {
    result.code = "zano-compact-scan-verified";
  }
  if (!all_spend_states_verified && balance_atomic > 0) {
    result.code = "zano-compact-scan-needs-native";
    result.error = "compact-spend-check-unavailable";
  }
  return result;
}
#else
std::optional<PrivacyLightWalletResult> zano_compact_snapshot(
  const std::map<std::string, std::string>&,
  const std::string&,
  const std::string&
) {
  return std::nullopt;
}
#endif

#ifndef _WIN32
std::filesystem::path executable_dir() {
#if defined(__APPLE__)
  uint32_t size = 0;
  (void)_NSGetExecutablePath(nullptr, &size);
  if (size == 0) return std::filesystem::current_path();
  std::string buffer(size, '\0');
  if (_NSGetExecutablePath(buffer.data(), &size) != 0) return std::filesystem::current_path();
  buffer.resize(std::strlen(buffer.c_str()));
  std::error_code ec;
  auto path = std::filesystem::weakly_canonical(std::filesystem::path(buffer), ec);
  if (ec) path = std::filesystem::path(buffer);
  return path.parent_path();
#else
  std::vector<char> buffer(PATH_MAX, '\0');
  ssize_t size = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
  if (size <= 0) return std::filesystem::current_path();
  buffer[static_cast<size_t>(size)] = '\0';
  return std::filesystem::path(buffer.data()).parent_path();
#endif
}

std::optional<std::filesystem::path> epic_module_path(const std::string& module) {
#if defined(__APPLE__)
  const auto name = std::filesystem::path("libaltbase_epic_" + module + ".dylib");
#else
  const auto name = std::filesystem::path("libaltbase_epic_" + module + ".so");
#endif
  const std::vector<std::filesystem::path> candidates = {
    executable_dir() / name,
    std::filesystem::current_path() / "native-core" / name,
    std::filesystem::current_path() / "native" / "epic_core" / "target" / "release" / name,
  };
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) return candidate;
  }
  return std::nullopt;
}

std::optional<std::filesystem::path> zano_core_dll_path() {
#if defined(__APPLE__)
  const auto name = std::filesystem::path("libaltbase_zano_core.dylib");
#else
  const auto name = std::filesystem::path("libaltbase_zano_core.so");
#endif
  const std::vector<std::filesystem::path> candidates = {
    executable_dir() / name,
    std::filesystem::current_path() / "native-core" / name,
    std::filesystem::current_path() / "native" / "core" / "build" / "vs2022-x64-release" / "bin" / "Release" / name,
  };
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) return candidate;
  }
  return std::nullopt;
}
#endif

std::string call_zano_core(const std::string& request) {
#ifdef _WIN32
  char* raw = altbase_zano_request(request.c_str());
  if (!raw) throw std::runtime_error("Zano wallet module returned no response");
  std::string response(raw);
  altbase_zano_free(raw);
  return response;
#else
  using RequestFn = char* (*)(const char*);
  using FreeFn = void (*)(char*);
  static std::once_flag load_once;
  static void* module = nullptr;
  static RequestFn request_fn = nullptr;
  static FreeFn free_fn = nullptr;
  static std::string load_error;

  std::call_once(load_once, [] {
    const auto path = zano_core_dll_path();
    if (!path.has_value()) {
      load_error = "Zano wallet module is unavailable";
      return;
    }
    module = dlopen(path->string().c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!module) {
      const char* error = dlerror();
      load_error = std::string("Zano wallet module failed to load") + (error ? ": " + std::string(error) : "");
      return;
    }
    request_fn = reinterpret_cast<RequestFn>(dlsym(module, "altbase_zano_request"));
    free_fn = reinterpret_cast<FreeFn>(dlsym(module, "altbase_zano_free"));
    if (!request_fn || !free_fn) {
      load_error = "Zano wallet module is incompatible";
    }
  });

  if (!load_error.empty()) throw std::runtime_error(load_error);
  char* raw = request_fn(request.c_str());
  if (!raw) throw std::runtime_error("Zano wallet module returned no response");
  std::string response(raw);
  free_fn(raw);
  return response;
#endif
}

std::string call_epic_core(const std::string& request, const std::string& action) {
#ifdef _WIN32
  const bool sending = action == "send" || action == "estimatemax";
  char* raw = sending
    ? altbase_epic_sender_request(request.c_str())
    : altbase_epic_state_request(request.c_str());
  if (!raw) throw std::runtime_error("optional wallet module returned no response");
  std::string response(raw);
  if (sending) {
    altbase_epic_sender_free(raw);
  } else {
    altbase_epic_state_free(raw);
  }
  return response;
#else
  using RequestFn = char* (*)(const char*);
  using FreeFn = void (*)(char*);
  struct EpicModule {
    void* handle = nullptr;
    RequestFn request = nullptr;
    FreeFn free = nullptr;
    std::string error;
  };
  const auto load_module = [](const std::string& name) {
    EpicModule loaded;
    const auto path = epic_module_path(name);
    if (!path.has_value()) {
      loaded.error = "optional wallet module is unavailable";
      return loaded;
    }
    loaded.handle = dlopen(path->string().c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!loaded.handle) {
      const char* error = dlerror();
      loaded.error = std::string("optional wallet module failed to load") + (error ? ": " + std::string(error) : "");
      return loaded;
    }
    const auto prefix = "altbase_epic_" + name;
    loaded.request = reinterpret_cast<RequestFn>(dlsym(loaded.handle, (prefix + "_request").c_str()));
    loaded.free = reinterpret_cast<FreeFn>(dlsym(loaded.handle, (prefix + "_free").c_str()));
    if (!loaded.request || !loaded.free) {
      loaded.error = "optional wallet module is incompatible";
    }
    return loaded;
  };
  static const EpicModule state = load_module("state");
  static const EpicModule sender = load_module("sender");
  const auto& module = (action == "send" || action == "estimatemax") ? sender : state;

  if (!module.error.empty()) throw std::runtime_error(module.error);
  char* raw = module.request(request.c_str());
  if (!raw) throw std::runtime_error("optional wallet module returned no response");
  std::string response(raw);
  module.free(raw);
  return response;
#endif
}

#ifdef _WIN32
Bytes sha_digest(const wchar_t* algorithm, const Bytes& bytes, size_t output_size) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) != 0) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
  }
  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  if (BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0) != 0) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash failed");
  }
  if (!bytes.empty() && BCryptHashData(hash_handle, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) != 0) {
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData failed");
  }
  Bytes hash(output_size);
  const auto status = BCryptFinishHash(hash_handle, hash.data(), static_cast<ULONG>(hash.size()), 0);
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptFinishHash failed");
  return hash;
}

Bytes sha256(const Bytes& bytes) {
  return sha_digest(BCRYPT_SHA256_ALGORITHM, bytes, 32);
}

Bytes hash256(const Bytes& bytes) {
  return sha256(sha256(bytes));
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data) {
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(HMAC-SHA512) failed");
  }
  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  if (BCryptCreateHash(
        alg,
        &hash_handle,
        nullptr,
        0,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0
      ) != 0) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash(HMAC-SHA512) failed");
  }
  if (!data.empty() && BCryptHashData(hash_handle, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0) != 0) {
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData(HMAC-SHA512) failed");
  }
  Bytes out(64);
  const auto status = BCryptFinishHash(hash_handle, out.data(), static_cast<ULONG>(out.size()), 0);
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptFinishHash(HMAC-SHA512) failed");
  return out;
}
#else
Bytes sha256(const Bytes& bytes) {
  Bytes hash(SHA256_DIGEST_LENGTH);
  SHA256(bytes.empty() ? nullptr : bytes.data(), bytes.size(), hash.data());
  return hash;
}

Bytes hash256(const Bytes& bytes) {
  return sha256(sha256(bytes));
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data) {
  Bytes out(SHA512_DIGEST_LENGTH);
  unsigned int out_len = 0;
  if (!HMAC(
        EVP_sha512(),
        key.empty() ? nullptr : key.data(),
        static_cast<int>(key.size()),
        data.empty() ? nullptr : data.data(),
        data.size(),
        out.data(),
        &out_len
      )) {
    throw std::runtime_error("HMAC-SHA512 failed");
  }
  out.resize(out_len);
  return out;
}
#endif

uint64_t load64(const uint8_t* p) {
  uint64_t out = 0;
  for (int i = 7; i >= 0; --i) out = (out << 8U) | p[i];
  return out;
}

void store64(uint8_t* p, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<uint8_t>(value & 0xffU);
    value >>= 8U;
  }
}

uint64_t rotr64(uint64_t value, int bits) {
  return (value >> bits) | (value << (64 - bits));
}

Bytes blake2b_256(const Bytes& input) {
  static constexpr std::array<uint64_t, 8> iv = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
  };
  static constexpr std::array<std::array<uint8_t, 16>, 12> sigma = {{
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
    {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
    {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
    {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
    {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
    {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
    {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
    {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
    {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
  }};

  auto h = iv;
  h[0] ^= 0x01010020U;
  uint64_t counter = 0;

  auto compress = [&](const uint8_t block[128], bool last) {
    std::array<uint64_t, 16> m{};
    for (size_t i = 0; i < 16; ++i) m[i] = load64(block + i * 8);
    std::array<uint64_t, 16> v{};
    for (size_t i = 0; i < 8; ++i) v[i] = h[i];
    for (size_t i = 0; i < 8; ++i) v[i + 8] = iv[i];
    v[12] ^= counter;
    if (last) v[14] = ~v[14];

    auto g = [&](size_t a, size_t b, size_t c, size_t d, uint64_t x, uint64_t y) {
      v[a] = v[a] + v[b] + x;
      v[d] = rotr64(v[d] ^ v[a], 32);
      v[c] = v[c] + v[d];
      v[b] = rotr64(v[b] ^ v[c], 24);
      v[a] = v[a] + v[b] + y;
      v[d] = rotr64(v[d] ^ v[a], 16);
      v[c] = v[c] + v[d];
      v[b] = rotr64(v[b] ^ v[c], 63);
    };

    for (size_t r = 0; r < 12; ++r) {
      const auto& s = sigma[r];
      g(0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (size_t i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
  };

  size_t offset = 0;
  while (input.size() - offset > 128) {
    uint8_t block[128]{};
    std::copy(input.begin() + static_cast<long long>(offset), input.begin() + static_cast<long long>(offset + 128), block);
    counter += 128;
    compress(block, false);
    offset += 128;
  }

  uint8_t block[128]{};
  const auto remaining = input.size() - offset;
  if (remaining > 0) {
    std::copy(input.begin() + static_cast<long long>(offset), input.end(), block);
  }
  counter += static_cast<uint64_t>(remaining);
  compress(block, true);

  Bytes out(32);
  uint8_t full[64]{};
  for (size_t i = 0; i < 8; ++i) store64(full + i * 8, h[i]);
  std::copy(full, full + 32, out.begin());
  return out;
}

Bytes base58check(const Bytes& payload) {
  Bytes data = payload;
  const auto checksum = hash256(payload);
  data.insert(data.end(), checksum.begin(), checksum.begin() + 4);

  std::vector<uint8_t> digits(1, 0);
  for (const auto byte : data) {
    int carry = byte;
    for (auto& digit : digits) {
      carry += digit << 8;
      digit = static_cast<uint8_t>(carry % 58);
      carry /= 58;
    }
    while (carry > 0) {
      digits.push_back(static_cast<uint8_t>(carry % 58));
      carry /= 58;
    }
  }

  std::string encoded;
  for (const auto byte : data) {
    if (byte == 0) encoded.push_back(BASE58[0]);
    else break;
  }
  for (auto it = digits.rbegin(); it != digits.rend(); ++it) encoded.push_back(BASE58[*it]);
  return Bytes(encoded.begin(), encoded.end());
}

std::string base58check_text(const Bytes& payload) {
  const auto encoded = base58check(payload);
  return std::string(encoded.begin(), encoded.end());
}

Bytes ser32(uint32_t value) {
  return Bytes{
    static_cast<uint8_t>((value >> 24U) & 0xffU),
    static_cast<uint8_t>((value >> 16U) & 0xffU),
    static_cast<uint8_t>((value >> 8U) & 0xffU),
    static_cast<uint8_t>(value & 0xffU),
  };
}

struct SecpContextDeleter {
  void operator()(secp256k1_context* ctx) const {
    secp256k1_context_destroy(ctx);
  }
};

Bytes public_key_compressed(secp256k1_context* ctx, const Bytes& private_key) {
  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_create(ctx, &pubkey, private_key.data()) != 1) {
    throw std::runtime_error("secp256k1 public key creation failed");
  }
  Bytes out(33);
  size_t out_len = out.size();
  secp256k1_ec_pubkey_serialize(ctx, out.data(), &out_len, &pubkey, SECP256K1_EC_COMPRESSED);
  out.resize(out_len);
  return out;
}

Bytes epic_derive_private_key(secp256k1_context* ctx, const Bytes& seed, const std::vector<uint32_t>& path) {
  const Bytes master_seed(EPIC_MASTER_SEED.begin(), EPIC_MASTER_SEED.end());
  const auto master = hmac_sha512(master_seed, seed);
  Bytes private_key(master.begin(), master.begin() + 32);
  Bytes chain_code(master.begin() + 32, master.end());

  if (secp256k1_ec_seckey_verify(ctx, private_key.data()) != 1) {
    throw std::runtime_error("Epic key derivation failed");
  }

  for (const auto index : path) {
    const auto pub = public_key_compressed(ctx, private_key);
    Bytes data(pub.begin(), pub.end());
    const auto index_bytes = ser32(index);
    data.insert(data.end(), index_bytes.begin(), index_bytes.end());
    const auto child = hmac_sha512(chain_code, data);
    Bytes tweak(child.begin(), child.begin() + 32);
    if (secp256k1_ec_seckey_verify(ctx, tweak.data()) != 1 ||
        secp256k1_ec_seckey_tweak_add(ctx, private_key.data(), tweak.data()) != 1) {
      throw std::runtime_error("Epic key derivation failed");
    }
    chain_code.assign(child.begin() + 32, child.end());
  }

  return private_key;
}

std::string epicbox_address_from_mnemonic(const std::string& mnemonic) {
  const auto entropy = bip39_mnemonic_to_entropy(mnemonic);
  std::unique_ptr<secp256k1_context, SecpContextDeleter> ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE));
  if (!ctx) throw std::runtime_error("failed to create secp256k1 context");

  const auto account_address_key = epic_derive_private_key(ctx.get(), entropy, {0, 1, 0});
  const auto hashed_key = blake2b_256(account_address_key);
  if (secp256k1_ec_seckey_verify(ctx.get(), hashed_key.data()) != 1) {
    throw std::runtime_error("Epic address derivation failed");
  }
  const auto public_key = public_key_compressed(ctx.get(), hashed_key);

  Bytes payload(EPICBOX_VERSION_MAINNET.begin(), EPICBOX_VERSION_MAINNET.end());
  payload.insert(payload.end(), public_key.begin(), public_key.end());
  return base58check_text(payload) + "@epicbox.epiccash.com";
}

std::string zano_address_from_mnemonic(const std::string& mnemonic) {
  const auto secret_derivation = zano_secret_derivation_from_mnemonic(mnemonic);
  const Bytes secret_derivation_bytes(secret_derivation.begin(), secret_derivation.end());
  std::ostringstream request;
  request << "{\"op\":\"address\",\"secretDerivationB64\":\""
          << base64_encode(secret_derivation_bytes)
          << "\"}";
  const auto response = call_zano_core(request.str());
  const auto address = regex_string(response, "address");
  if (address.empty()) throw std::runtime_error(json_error_message(response));
  return address;
}

PrivacyLightWalletResult epic_wallet(const std::map<std::string, std::string>& params, const std::string& action) {
  const auto mnemonic = get_param(params, "phrase");
  if (mnemonic.empty()) {
    if (action != "snapshot") {
      auto result = not_ready("epic-wallet-unlock-required", "Epic address derivation requires the local wallet to be unlocked.");
      result.server_status = scan_info(params, "epic");
      return result;
    }
    PrivacyLightWalletResult result;
    result.ok = true;
    result.code = "epic-native-snapshot-needs-unlock";
    result.balance = "0";
    result.spendable = "0";
    result.transactions = "[]";
    result.server_status = scan_info(params, "epic");
    return result;
  }

  const auto secret = privacy_wallet_secret({{"coin", "epic"}, {"phrase", mnemonic}});
  const auto epic_dir = epic_work_dir(params, secret.scope);
#ifdef _WIN32
  const auto epic_dir_text = epic_dir;
#else
  const auto epic_dir_text = epic_dir.string();
  std::filesystem::create_directories(epic_dir);
  (void)import_epic_wallet_backup_from_cache(epic_dir, secret.scope, params);
#endif
  std::string epic_server_status;
  uint64_t epic_restore_start = 0;
  uint64_t epic_progress_start = 0;
  uint64_t epic_tip_height = 0;
  bool epic_progress = false;
  if (action == "snapshot") {
    epic_server_status = scan_info(params, "epic");
    const auto tip_text = regex_number(epic_server_status, "headers").empty()
      ? regex_number(epic_server_status, "blocks")
      : regex_number(epic_server_status, "headers");
    const auto restore_start = get_param(params, "restoreStartHeight");
    if (is_decimal_number(restore_start) && !tip_text.empty()) {
      epic_restore_start = parse_u64_or_zero(restore_start);
      epic_tip_height = parse_u64_or_zero(tip_text);
      if (epic_restore_start > epic_tip_height) epic_restore_start = epic_tip_height;
      epic_progress_start = epic_progress_start_height(params, secret.scope, epic_restore_start, epic_tip_height);
      epic_progress = true;
      emit_privacy_recovery_progress(params, "epic", epic_progress_start, epic_progress_start, epic_tip_height);
    }
  }

  PrivacyLightWalletResult result;
  try {
    std::ostringstream request;
    request << "{\"action\":\"" << json_escape(action) << "\","
            << "\"phrase\":\"" << json_escape(mnemonic) << "\","
            << "\"password\":\"" << json_escape(secret.engine_password) << "\","
            << "\"dataDir\":\"" << json_escape(epic_dir_text) << "\","
            << "\"nodeUrl\":\"" << json_escape(epic_node_url(params)) << "\"";
    const auto restore_start_height = get_param(params, "restoreStartHeight");
    if (is_decimal_number(restore_start_height)) {
      request << ",\"restoreStartHeight\":" << restore_start_height;
    }
    if (action == "send") {
      request << ",\"to\":\"" << json_escape(get_param(params, "to")) << "\","
              << "\"amount\":\"" << json_escape(get_param(params, "amount")) << "\","
              << "\"fee\":\"" << json_escape(get_param(params, "fee")) << "\","
              << "\"sendMax\":\"" << json_escape(get_param(params, "sendMax")) << "\","
              << "\"memo\":\"" << json_escape(get_param(params, "memo")) << "\"";
    } else if (action == "estimatemax") {
      request << ",\"fee\":\"" << json_escape(get_param(params, "fee")) << "\","
              << "\"sendMax\":\"true\"";
    }
    request << "}";

    const auto response = call_epic_core(request.str(), action);
    result.ok = regex_bool(response, "ok");
    result.code = regex_string(response, "code");
    result.error = regex_string(response, "error");
    result.address = regex_string(response, "address");
    result.balance = regex_string(response, "balance");
    result.spendable = regex_string(response, "spendable");
    result.txid = regex_string(response, "txid");
    result.amount = regex_string(response, "amount");
    result.fee = regex_string(response, "fee");
    result.transactions = json_array_field(response, "transactions");
    result.last_scanned_height = regex_number(response, "lastScannedHeight");
    if (result.last_scanned_height.empty()) result.last_scanned_height = regex_number(response, "last_scanned_height");
    if (result.address.empty()) result.address = epicbox_address_from_mnemonic(mnemonic);
    if (result.balance.empty()) result.balance = "0";
    if (result.spendable.empty()) result.spendable = result.balance;
    if (result.transactions.empty()) result.transactions = "[]";
  } catch (const std::exception& e) {
    result = not_ready("epic-native-wallet-error", e.what());
    result.address = epicbox_address_from_mnemonic(mnemonic);
  }
  result.server_status = epic_server_status.empty() ? scan_info(params, "epic") : epic_server_status;
  attach_epic_wallet_backup(result, params, secret.scope);
  if (epic_progress) emit_privacy_recovery_progress(params, "epic", epic_progress_start, epic_tip_height + 1, epic_tip_height);
  return result;
}

PrivacyLightWalletResult zano_wallet(const std::map<std::string, std::string>& params, const std::string& action) {
  const auto mnemonic = get_param(params, "phrase");
  if (mnemonic.empty()) {
    if (action != "snapshot") {
      auto result = not_ready("zano-wallet-unlock-required", "Zano address derivation requires the local wallet to be unlocked.");
      result.server_status = scan_info(params, "zano");
      return result;
    }
    PrivacyLightWalletResult result;
    result.ok = true;
    result.code = "zano-native-snapshot-needs-unlock";
    result.balance = "0";
    result.spendable = "0";
    result.transactions = "[]";
    result.server_status = scan_info(params, "zano");
    return result;
  }

  const auto secret = privacy_wallet_secret({{"coin", "zano"}, {"phrase", mnemonic}});
  const auto address = zano_address_from_mnemonic(mnemonic);

  if (action == "ensure") {
    PrivacyLightWalletResult result;
    result.ok = true;
    result.code = "zano-local-address";
    result.address = address;
    result.balance = "0";
    result.spendable = "0";
    result.transactions = "[]";
    result.server_status = scan_info(params, "zano");
    return result;
  }

  if (action == "warm") {
    PrivacyLightWalletResult result;
    result.ok = true;
    result.code = "zano-local-address";
    result.address = address;
    result.balance = "0";
    result.spendable = "0";
    result.transactions = "[]";
    result.server_status = scan_info(params, "zano");
    try {
      std::lock_guard<std::mutex> lock(zano_mutex);
      auto& session = ensure_zano_wallet(params, mnemonic, secret);
      wait_for_zano_initial_sync(session, action == "warm" ? ZANO_BACKGROUND_WARM_ATTEMPTS : 1, &params);
      try {
        (void)zano_wallet_rpc(session.wallet_id, "store", "{}", session.initial_sync_pending ? 1 : 30);
      } catch (...) {
      }
      result.address = session.address;
      result.code = session.initial_sync_pending ? "zano-native-wallet-syncing" : "zano-native-wallet-ready";
      try {
        const auto status = zano_wallet_status(session.wallet_id);
        set_zano_wallet_height(result, status);
        if (get_param(params, "debugZanoStatus") == "true") result.error = status;
      } catch (...) {
      }
      uint64_t unlocked = 0;
      std::string raw_balance;
      const auto expected_spendable = zano_expected_spendable_units(params);
      const auto balance_busy_attempts = (!session.initial_sync_pending || expected_spendable > 0)
        ? ZANO_SEND_RPC_BUSY_ATTEMPTS
        : 4;
      if (populate_zano_balance_result(result, session.wallet_id, balance_busy_attempts, &unlocked, &raw_balance)) {
        if (get_param(params, "debugRawBalance") == "true") result.error = raw_balance;
        if (unlocked > 0 && (expected_spendable == 0 || unlocked >= expected_spendable)) {
          session.initial_sync_pending = false;
          result.code = "zano-native-wallet-ready";
        }
        if (expected_spendable > 0 && unlocked == 0) {
          session.initial_sync_pending = true;
          result.code = "zano-native-wallet-syncing";
        }
      } else {
        if (get_param(params, "debugRawBalance") == "true" && !raw_balance.empty()) result.error = raw_balance;
        result.code = "zano-native-wallet-syncing";
      }
      try {
        (void)zano_wallet_rpc(session.wallet_id, "store", "{}", session.initial_sync_pending ? 1 : 30);
      } catch (...) {
      }
      attach_zano_wallet_backup(result, params, session);
    } catch (...) {
      // Address derivation is still valid; warm-up will retry on the next unlock/snapshot.
    }
    return result;
  }

  std::optional<PrivacyLightWalletResult> compact_snapshot;
  if (action == "snapshot" && get_param(params, "verifyCompact") == "true") {
    if (const auto compact = zano_compact_snapshot(params, mnemonic, address)) {
      if (get_param(params, "compactOnly") == "true") return *compact;
      const auto compact_balance = parse_decimal_units(compact->balance.empty() ? "0" : compact->balance, ZANO_ATOMIC_UNITS);
      if (compact_balance == 0) return *compact;
      compact_snapshot = compact;
      if (!zano_prepared_wallet_available(params, secret)) {
        auto pending = *compact_snapshot;
        if (pending.code != "zano-compact-scan-verified") {
          pending.code = "zano-compact-scan-needs-native";
        }
        pending.error = pending.error.empty() ? "native-wallet-restore-pending" : pending.error;
        return pending;
      }
      // A positive compact result is only a fast pre-scan. The native wallet
      // must verify spent state before the UI can trust the visible balance.
    }
  }

  PrivacyLightWalletResult result;
  try {
    std::lock_guard<std::mutex> lock(zano_mutex);
    auto& session = ensure_zano_wallet(params, mnemonic, secret);
    result.ok = true;
    result.code = "zano-native-wallet";
    result.address = session.address;
    result.server_status = scan_info(params, "zano");
    uint64_t send_amount = 0;
    uint64_t send_fee = 0;
    uint64_t send_required = 0;
    if (action == "send") {
      send_amount = parse_decimal_units(get_param(params, "amount"), ZANO_ATOMIC_UNITS);
      const auto fee_param = get_param(params, "fee");
      send_fee = fee_param.empty() ? ZANO_DEFAULT_FEE : parse_decimal_units(fee_param, ZANO_ATOMIC_UNITS);
      if (send_amount > std::numeric_limits<uint64_t>::max() - send_fee) {
        throw std::runtime_error("Zano amount plus fee is too large");
      }
      send_required = send_amount + send_fee;
    }
    wait_for_zano_initial_sync(session, action == "send"
      ? ZANO_SEND_READY_ATTEMPTS
      : (action == "snapshot" ? 2 : ZANO_INITIAL_SYNC_ATTEMPTS), &params);
    try {
      (void)zano_wallet_rpc(session.wallet_id, "store", "{}", session.initial_sync_pending ? 1 : 30);
    } catch (...) {
    }
    try {
      const auto status = zano_wallet_status(session.wallet_id);
      set_zano_wallet_height(result, status);
      if (get_param(params, "debugZanoStatus") == "true") result.error = status;
    } catch (...) {
    }
    if (session.initial_sync_pending) {
      uint64_t unlocked = 0;
      std::string raw_balance;
      if (populate_zano_balance_result(result, session.wallet_id, action == "send" ? ZANO_SEND_RPC_BUSY_ATTEMPTS : 4, &unlocked, &raw_balance)
          && unlocked > 0
          && (action != "send" || unlocked >= send_required)) {
        session.initial_sync_pending = false;
      }
      if (get_param(params, "debugRawBalance") == "true" && !raw_balance.empty()) result.error = raw_balance;
    }
    if (session.initial_sync_pending) {
      if (action == "send") {
        result.ok = false;
        result.code = "zano-native-wallet-syncing";
        result.error = "Zano wallet is preparing local spend data. Please wait a moment and try again.";
        result.transactions = "[]";
        attach_zano_wallet_backup(result, params, session);
        return result;
      }
      result.code = "zano-native-wallet-syncing";
      result.transactions = "[]";
      attach_zano_wallet_backup(result, params, session);
    } else if (action == "send") {
      const auto to = get_param(params, "to");
      if (to.empty()) throw std::runtime_error("Destination address is required");
      const auto balance = zano_wallet_balance(session.wallet_id, 2);
      if (balance.unlocked < send_required) {
        std::ostringstream message;
        message << "Zano native wallet spendable balance is not ready. Required: "
                << units_to_decimal(send_required, ZANO_ATOMIC_UNITS)
                << ", Available: " << units_to_decimal(balance.unlocked, ZANO_ATOMIC_UNITS)
                << ". Please wait for Zano sync and try again.";
        throw std::runtime_error(message.str());
      }
      const auto memo = get_param(params, "memo");
      std::ostringstream body;
      body << "{\"destinations\":[{\"amount\":" << send_amount
           << ",\"address\":\"" << json_escape(to) << "\"}],"
           << "\"fee\":" << send_fee
           << ",\"mixin\":15,"
           << "\"payment_id\":\"\","
           << "\"comment\":\"" << json_escape(memo) << "\","
           << "\"push_payer\":true,"
           << "\"hide_receiver\":false,"
           << "\"service_entries\":[],"
           << "\"service_entries_permanent\":false}";
      const auto send_response = zano_wallet_rpc(session.wallet_id, "transfer", body.str(), ZANO_SEND_RPC_BUSY_ATTEMPTS);
      const auto txid = regex_string(send_response, "tx_hash");
      if (txid.empty()) throw std::runtime_error("Zano transfer did not return a tx hash");
      result.txid = txid;
      result.fee = units_to_decimal(send_fee, ZANO_ATOMIC_UNITS);
      result.transactions = "[]";
      try {
        (void)zano_wallet_rpc(session.wallet_id, "store", "{}", 1);
      } catch (...) {
      }
      attach_zano_wallet_backup(result, params, session);
      return result;
    } else {
      const auto snapshot_rpc_attempts = action == "send" ? ZANO_SEND_RPC_BUSY_ATTEMPTS : ZANO_SNAPSHOT_RPC_BUSY_ATTEMPTS;
      const auto balance_response = zano_wallet_rpc(session.wallet_id, "getbalance", "{}", snapshot_rpc_attempts);
      const auto balance_units = regex_number(balance_response, "balance");
      const auto unlocked_units = regex_number(balance_response, "unlocked_balance");
      result.balance = balance_units.empty() ? "0" : units_to_decimal(std::stoull(balance_units), ZANO_ATOMIC_UNITS);
      result.spendable = unlocked_units.empty() ? result.balance : units_to_decimal(std::stoull(unlocked_units), ZANO_ATOMIC_UNITS);

      result.transactions = zano_wallet_rpc(
        session.wallet_id,
        "get_recent_txs_and_info2",
        zano_recent_history_request(),
        snapshot_rpc_attempts
      );
      try {
        (void)zano_wallet_rpc(session.wallet_id, "store", "{}", action == "send" ? 30 : ZANO_SNAPSHOT_STORE_BUSY_ATTEMPTS);
      } catch (...) {
      }
      attach_zano_wallet_backup(result, params, session);
    }
  } catch (const std::exception& e) {
    const std::string error = e.what();
    if (error.find("BUSY") != std::string::npos) {
      if (action == "send") {
        result = not_ready("zano-native-wallet-syncing", "Zano wallet is busy finishing its local sync. Please wait a moment and try again.");
      } else {
        result.ok = true;
        result.code = "zano-native-wallet-syncing";
        result.error.clear();
        result.transactions = "[]";
      }
    } else {
      result = not_ready("zano-native-wallet-error", error);
    }
    result.address = zano_address_from_mnemonic(mnemonic);
    result.server_status = scan_info(params, "zano");
    if (result.balance.empty()) result.balance = "0";
    if (result.spendable.empty()) result.spendable = result.balance;
    if (result.transactions.empty()) result.transactions = "[]";
    try {
      std::lock_guard<std::mutex> lock(zano_mutex);
      if (zano_session.initialized && zano_session.scope == secret.scope && zano_session.address == address) {
        attach_zano_wallet_backup(result, params, zano_session);
      }
    } catch (...) {
    }
  }
  if (compact_snapshot.has_value()) {
    if (result.code == "zano-native-wallet-syncing") {
      auto pending = *compact_snapshot;
      if (pending.code != "zano-compact-scan-verified") {
        pending.code = "zano-compact-scan-needs-native";
      }
      pending.error = result.error.empty() ? "native-wallet-verification-pending" : result.error;
      return pending;
    }
    const auto compact_balance = parse_decimal_units(compact_snapshot->balance.empty() ? "0" : compact_snapshot->balance, ZANO_ATOMIC_UNITS);
    const auto native_balance = parse_decimal_units(result.balance.empty() ? "0" : result.balance, ZANO_ATOMIC_UNITS);
    if (
      (compact_snapshot->code == "zano-compact-scan-verified" || compact_balance == native_balance)
      && json_array_object_count(compact_snapshot->transactions) > json_array_object_count(result.transactions)
    ) {
      result.transactions = compact_snapshot->transactions;
    }
    if (result.scan_state.empty()) result.scan_state = compact_snapshot->scan_state;
    if (result.last_scanned_height.empty()) result.last_scanned_height = compact_snapshot->last_scanned_height;
  }
  return result;
}

PrivacyLightWalletResult source_integration_required(
  const std::map<std::string, std::string>& params,
  const std::string& coin
) {
  auto result = not_ready(
    coin + "-native-source-integration-required",
    "This privacy wallet must be linked from the coin source/library inside native-core. External wallet binaries are disabled."
  );
  result.server_status = scan_info(params, coin);
  return result;
}

}  // namespace

PrivacyLightWalletResult privacy_light_wallet(const std::map<std::string, std::string>& params) {
  const auto coin = lower(get_param(params, "coin"));
  const auto action = lower(get_param(params, "action"));
  const auto mnemonic = get_param(params, "phrase");

#if defined(ALTBASE_ZANO_WALLET_ONLY)
  if (coin != "zano") return not_ready("bad-coin", "Unsupported Zano wallet coin");
#elif defined(ALTBASE_EPIC_WALLET_ONLY)
  if (coin != "epic") return not_ready("bad-coin", "Unsupported Epic wallet coin");
#else
  if (coin != "zano" && coin != "epic") {
    return not_ready("bad-coin", "Unsupported native privacy coin");
  }
#endif
  if (action != "ensure" && action != "warm" && action != "snapshot" && action != "send" && action != "estimatemax") {
    return not_ready("bad-action", "Unsupported native privacy light-wallet action");
  }
  if ((action == "ensure" || action == "warm" || action == "send" || action == "estimatemax") && mnemonic.empty()) {
    return not_ready("missing-phrase", "Wallet phrase is required for native privacy wallet");
  }

  if (!mnemonic.empty()) {
    (void)privacy_wallet_secret({{"coin", coin}, {"phrase", mnemonic}});
  }

#if defined(ALTBASE_ZANO_WALLET_ONLY)
  return zano_wallet(params, action);
#elif defined(ALTBASE_EPIC_WALLET_ONLY)
  return epic_wallet(params, action);
#else
  if (coin == "epic") return epic_wallet(params, action);
  if (coin == "zano") return zano_wallet(params, action);
  return source_integration_required(params, coin);
#endif
}

}  // namespace altbase
