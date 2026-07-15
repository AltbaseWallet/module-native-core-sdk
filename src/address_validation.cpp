#include "address_validation.hpp"

#include <algorithm>
#include <array>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

constexpr const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr const char* CASH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t BECH32_CONST = 1U;
constexpr uint32_t BECH32M_CONST = 0x2bc830a3U;

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string trim_address(std::string value) {
  value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }), value.end());
  return value;
}

int to_int(const std::map<std::string, std::string>& params, const std::string& key, int fallback = -1) {
  const auto it = params.find(key);
  if (it == params.end() || it->second.empty()) return fallback;
  try {
    return std::stoi(it->second);
  } catch (...) {
    return fallback;
  }
}

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

std::vector<uint8_t> hash256(const std::vector<uint8_t>& bytes);

std::string bytes_hex(const std::vector<uint8_t>& bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : bytes) out << std::setw(2) << static_cast<int>(byte);
  return out.str();
}

std::string p2pkh_script_hex(const std::vector<uint8_t>& hash) {
  return "76a914" + bytes_hex(hash) + "88ac";
}

std::string p2sh_script_hex(const std::vector<uint8_t>& hash) {
  return "a914" + bytes_hex(hash) + "87";
}

std::string witness_script_hex(int version, const std::vector<uint8_t>& program) {
  if (version < 0 || version > 16) throw std::runtime_error("invalid witness version");
  std::ostringstream out;
  const int opcode = version == 0 ? 0 : 0x50 + version;
  out << std::hex << std::setfill('0') << std::setw(2) << opcode
      << std::setw(2) << program.size() << bytes_hex(program);
  return out.str();
}

std::string base58check_text(const std::vector<uint8_t>& payload) {
  auto data = payload;
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
  return encoded;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& bytes) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");
  }

  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  if (BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0) != 0) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash(SHA256) failed");
  }

  const auto data_status = BCryptHashData(
    hash_handle,
    const_cast<PUCHAR>(bytes.data()),
    static_cast<ULONG>(bytes.size()),
    0
  );
  if (data_status != 0) {
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData(SHA256) failed");
  }

  std::vector<uint8_t> hash(32);
  const auto status = BCryptFinishHash(
    hash_handle,
    hash.data(),
    static_cast<ULONG>(hash.size()),
    0
  );
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptFinishHash(SHA256) failed");
  return hash;
#else
  std::vector<uint8_t> hash(32);
  unsigned int len = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), hash.data(), &len, EVP_sha256(), nullptr) != 1 || len != hash.size()) {
    throw std::runtime_error("EVP_Digest(SHA256) failed");
  }
  return hash;
#endif
}

std::vector<uint8_t> hash256(const std::vector<uint8_t>& bytes) {
  return sha256(sha256(bytes));
}

int base58_value(char c) {
  const char* p = std::find(BASE58, BASE58 + 58, c);
  return p == BASE58 + 58 ? -1 : static_cast<int>(p - BASE58);
}

std::optional<std::vector<uint8_t>> base58_decode(const std::string& input) {
  std::vector<uint8_t> bytes;
  bytes.reserve(input.size());

  for (const char c : input) {
    const int digit = base58_value(c);
    if (digit < 0) return std::nullopt;

    int carry = digit;
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
      carry += 58 * (*it);
      *it = static_cast<uint8_t>(carry & 0xff);
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.insert(bytes.begin(), static_cast<uint8_t>(carry & 0xff));
      carry >>= 8;
    }
  }

  size_t leading = 0;
  while (leading < input.size() && input[leading] == '1') ++leading;
  bytes.insert(bytes.begin(), leading, 0);
  return bytes;
}

std::optional<std::vector<uint8_t>> base58check_payload(const std::string& address, std::string& error) {
  const auto decoded = base58_decode(address);
  if (!decoded) {
    error = "invalid base58 character";
    return std::nullopt;
  }
  if (decoded->size() < 5) {
    error = "address too short";
    return std::nullopt;
  }

  const std::vector<uint8_t> payload(decoded->begin(), decoded->end() - 4);
  const auto checksum = hash256(payload);
  for (size_t i = 0; i < 4; ++i) {
    if ((*decoded)[decoded->size() - 4 + i] != checksum[i]) {
      error = "invalid base58 checksum";
      return std::nullopt;
    }
  }
  return payload;
}

int cash_value(char c) {
  const char* p = std::find(CASH32, CASH32 + 32, static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  return p == CASH32 + 32 ? -1 : static_cast<int>(p - CASH32);
}

std::vector<int> hrp_expand(const std::string& hrp) {
  std::vector<int> out;
  out.reserve(hrp.size() * 2 + 1);
  for (const char c : hrp) out.push_back(static_cast<unsigned char>(c) >> 5);
  out.push_back(0);
  for (const char c : hrp) out.push_back(static_cast<unsigned char>(c) & 31);
  return out;
}

uint32_t bech32_polymod(const std::vector<int>& values) {
  constexpr std::array<uint32_t, 5> gen = {0x3b6a57b2U, 0x26508e6dU, 0x1ea119faU, 0x3d4233ddU, 0x2a1462b3U};
  uint32_t chk = 1;
  for (const int value : values) {
    const uint32_t top = chk >> 25U;
    chk = ((chk & 0x1ffffffU) << 5U) ^ static_cast<uint32_t>(value);
    for (int i = 0; i < 5; ++i) {
      if (((top >> i) & 1U) != 0U) chk ^= gen[static_cast<size_t>(i)];
    }
  }
  return chk;
}

std::optional<std::vector<uint8_t>> convert_bits(const std::vector<int>& data, int from_bits, int to_bits, bool pad) {
  int acc = 0;
  int bits = 0;
  const int maxv = (1 << to_bits) - 1;
  std::vector<uint8_t> out;
  for (const int value : data) {
    if (value < 0 || (value >> from_bits) != 0) return std::nullopt;
    acc = (acc << from_bits) | value;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits > 0) out.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
  } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
    return std::nullopt;
  }
  return out;
}

AddressValidationResult validate_bech32(const std::string& address, const std::string& expected_hrp) {
  AddressValidationResult result;
  const bool has_lower = std::any_of(address.begin(), address.end(), [](unsigned char c) { return std::islower(c) != 0; });
  const bool has_upper = std::any_of(address.begin(), address.end(), [](unsigned char c) { return std::isupper(c) != 0; });
  if (has_lower && has_upper) {
    result.error = "mixed case bech32";
    return result;
  }

  const std::string value = lower(address);
  const auto pos = value.rfind('1');
  if (pos == std::string::npos || pos == 0 || pos + 7 > value.size()) {
    result.error = "invalid bech32 separator";
    return result;
  }

  const std::string hrp = value.substr(0, pos);
  if (expected_hrp.empty()) {
    result.error = "bech32 is not configured for this coin";
    return result;
  }
  if (hrp != lower(expected_hrp)) {
    result.error = "wrong bech32 hrp";
    return result;
  }

  std::vector<int> data;
  for (size_t i = pos + 1; i < value.size(); ++i) {
    const int v = cash_value(value[i]);
    if (v < 0) {
      result.error = "invalid bech32 character";
      return result;
    }
    data.push_back(v);
  }

  auto values = hrp_expand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  const auto checksum = bech32_polymod(values);
  if (checksum != BECH32_CONST && checksum != BECH32M_CONST) {
    result.error = "invalid bech32 checksum";
    return result;
  }

  const std::vector<int> payload(data.begin(), data.end() - 6);
  if (payload.empty() || payload[0] < 0 || payload[0] > 16) {
    result.error = "unsupported witness version";
    return result;
  }
  const int witness_version = payload[0];
  const auto program = convert_bits(std::vector<int>(payload.begin() + 1, payload.end()), 5, 8, false);
  if (!program || (program->size() != 20 && program->size() != 32)) {
    result.error = "unsupported witness program";
    return result;
  }
  if (witness_version == 0 && checksum != BECH32_CONST) {
    result.error = "invalid bech32 checksum";
    return result;
  }
  if (witness_version > 0 && checksum != BECH32M_CONST) {
    result.error = "invalid bech32m checksum";
    return result;
  }
  if (witness_version == 1 && program->size() != 32) {
    result.error = "unsupported taproot program";
    return result;
  }
  result.is_valid = true;
  result.format = "bech32";
  result.script_kind = witness_version == 1 ? "p2tr" : (program->size() == 20 ? "p2wpkh" : "p2wsh");
  result.script_pub_key = witness_script_hex(witness_version, *program);
  return result;
}

std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& program) {
  const auto normalized = lower(hrp);
  std::vector<int> data{0};
  const auto converted = convert_bits(std::vector<int>(program.begin(), program.end()), 8, 5, true);
  if (!converted) throw std::runtime_error("bech32 conversion failed");
  data.insert(data.end(), converted->begin(), converted->end());

  auto values = hrp_expand(normalized);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  const auto mod = bech32_polymod(values) ^ 1U;

  std::string out = normalized + "1";
  for (const auto value : data) out.push_back(CASH32[static_cast<size_t>(value)]);
  for (int i = 0; i < 6; ++i) {
    out.push_back(CASH32[static_cast<size_t>((mod >> (5 * (5 - i))) & 31U)]);
  }
  return out;
}

uint64_t cash_polymod(const std::vector<int>& values) {
  constexpr std::array<uint64_t, 5> gen = {
    0x98f2bc8e61ULL, 0x79b76d99e2ULL, 0xf33e5fb3c4ULL, 0xae2eabe2a8ULL, 0x1e4f43e470ULL
  };
  uint64_t c = 1;
  for (const int value : values) {
    const uint64_t c0 = c >> 35U;
    c = ((c & 0x07ffffffffULL) << 5U) ^ static_cast<uint64_t>(value);
    for (int i = 0; i < 5; ++i) {
      if (((c0 >> i) & 1ULL) != 0ULL) c ^= gen[static_cast<size_t>(i)];
    }
  }
  return c ^ 1ULL;
}

AddressValidationResult validate_legacy_bch2_cashaddr_payload(
  const std::vector<int>& data,
  const std::string& body,
  size_t colon
);

AddressValidationResult validate_cashaddr(const std::string& address, const std::string& expected_prefix) {
  AddressValidationResult result;
  const auto colon = address.find(':');
  if (expected_prefix.empty()) {
    result.error = "cashaddr is not configured for this coin";
    return result;
  }

  const std::string prefix = colon == std::string::npos ? lower(expected_prefix) : lower(address.substr(0, colon));
  const std::string body = colon == std::string::npos ? lower(address) : lower(address.substr(colon + 1));
  if (prefix != lower(expected_prefix)) {
    result.error = "wrong cashaddr prefix";
    return result;
  }
  if (body.size() <= 8) {
    result.error = "cashaddr body too short";
    return result;
  }

  std::vector<int> data;
  for (const char c : body) {
    const int v = cash_value(c);
    if (v < 0) {
      result.error = "invalid cashaddr character";
      return result;
    }
    data.push_back(v);
  }

  std::vector<int> values;
  for (const char c : prefix) values.push_back(static_cast<unsigned char>(c) & 31);
  values.push_back(0);
  values.insert(values.end(), data.begin(), data.end());
  if (cash_polymod(values) != 0) {
    result.error = "invalid cashaddr checksum";
    return result;
  }

  const std::vector<int> payload5(data.begin(), data.end() - 8);
  const auto payload = convert_bits(payload5, 5, 8, false);
  if (!payload || payload->size() < 21) {
    return validate_legacy_bch2_cashaddr_payload(data, body, colon);
  }
  const int type = ((*payload)[0] >> 3) & 0x1f;
  if (type != 0 && type != 1) {
    result.error = "unsupported cashaddr type";
    return result;
  }
  const std::vector<uint8_t> hash(payload->begin() + 1, payload->end());
  if (hash.size() != 20) {
    result.error = "unsupported cashaddr hash length";
    return result;
  }
  result.is_valid = true;
  result.format = colon == std::string::npos ? "cashaddr-plain" : "cashaddr";
  result.script_kind = type == 0 ? "p2pkh" : "p2sh";
  result.script_pub_key = type == 0 ? p2pkh_script_hex(hash) : p2sh_script_hex(hash);
  return result;
}

AddressValidationResult validate_legacy_bch2_cashaddr_payload(
  const std::vector<int>& data,
  const std::string& body,
  const size_t colon
) {
  AddressValidationResult result;
  if (body.size() != 41 || data.size() != 41) {
    result.error = "invalid cashaddr payload";
    return result;
  }

  // Early Altbase/BCH2 builds encoded CashAddr as:
  //   version-5bit || convertBits(hash160, 8, 5)
  // instead of convertBits(version-byte || hash160, 8, 5).
  // Some BCH2 services still use that 41-character body. It maps to the same
  // P2PKH/P2SH script, so accept it for sending while keeping standard
  // CashAddr support above.
  const std::vector<int> payload5(data.begin(), data.end() - 8);
  if (payload5.size() != 33) {
    result.error = "invalid cashaddr payload";
    return result;
  }

  const int type = (payload5[0] >> 3) & 0x1f;
  if (type != 0 && type != 1) {
    result.error = "unsupported cashaddr type";
    return result;
  }

  const auto hash_bytes = convert_bits(std::vector<int>(payload5.begin() + 1, payload5.end()), 5, 8, false);
  if (!hash_bytes || hash_bytes->size() != 20) {
    result.error = "unsupported cashaddr hash length";
    return result;
  }

  result.is_valid = true;
  result.format = colon == std::string::npos ? "cashaddr-plain-legacy" : "cashaddr-legacy";
  result.script_kind = type == 0 ? "p2pkh" : "p2sh";
  result.script_pub_key = type == 0 ? p2pkh_script_hex(*hash_bytes) : p2sh_script_hex(*hash_bytes);
  return result;
}

std::string cashaddr_encode(const std::string& prefix, int type, const std::vector<uint8_t>& hash) {
  if (hash.size() != 20) throw std::runtime_error("unsupported cashaddr hash length");
  const auto normalized = lower(prefix);
  const int version = type << 3;
  std::vector<int> payload8{version};
  payload8.insert(payload8.end(), hash.begin(), hash.end());
  const auto payload5 = convert_bits(payload8, 8, 5, true);
  if (!payload5) throw std::runtime_error("cashaddr conversion failed");

  std::vector<int> checksum_base;
  for (const char c : normalized) checksum_base.push_back(static_cast<unsigned char>(c) & 31);
  checksum_base.push_back(0);
  checksum_base.insert(checksum_base.end(), payload5->begin(), payload5->end());

  auto checksum_input = checksum_base;
  checksum_input.insert(checksum_input.end(), 8, 0);
  const auto checksum_value = cash_polymod(checksum_input);

  std::string body;
  for (const auto value : *payload5) body.push_back(CASH32[static_cast<size_t>(value)]);
  for (int i = 0; i < 8; ++i) {
    body.push_back(CASH32[static_cast<size_t>((checksum_value >> (5 * (7 - i))) & 31ULL)]);
  }
  return normalized + ":" + body;
}

AddressValidationResult validate_base58(const std::string& address, int p2pkh, int p2sh) {
  AddressValidationResult result;
  std::string error;
  const auto payload = base58check_payload(address, error);
  if (!payload) {
    result.error = error;
    return result;
  }
  if (payload->size() != 21) {
    result.error = "invalid base58 payload length";
    return result;
  }

  const int version = (*payload)[0];
  const std::vector<uint8_t> hash(payload->begin() + 1, payload->end());
  if (version == p2pkh) {
    result.is_valid = true;
    result.format = "legacy";
    result.script_kind = "p2pkh";
    result.script_pub_key = p2pkh_script_hex(hash);
    return result;
  }
  if (version == p2sh) {
    result.is_valid = true;
    result.format = "legacy";
    result.script_kind = "p2sh";
    result.script_pub_key = p2sh_script_hex(hash);
    return result;
  }
  result.error = "wrong address prefix";
  return result;
}

bool looks_like_bech32(const std::string& value) {
  const auto one = value.rfind('1');
  return one != std::string::npos && one > 0 && one + 7 <= value.size();
}

bool looks_like_configured_bech32(const std::string& value, const std::string& expected_hrp) {
  if (expected_hrp.empty() || !looks_like_bech32(value)) return false;
  const auto normalized = lower(value);
  const auto hrp = lower(expected_hrp) + "1";
  return normalized.rfind(hrp, 0) == 0;
}

bool looks_like_cashaddr_plain(const std::string& value) {
  if (value.size() < 40) return false;
  return std::all_of(value.begin(), value.end(), [](char c) { return cash_value(c) >= 0; });
}

}  // namespace

AddressValidationResult validate_address(const std::map<std::string, std::string>& params) {
  const auto address = trim_address(get_param(params, "address"));
  if (address.empty()) return {false, "", "", "", "address is required"};

  const int p2pkh = to_int(params, "p2pkhPrefix");
  const int p2sh = to_int(params, "p2shPrefix");
  const auto bech32 = get_param(params, "bech32Hrp");
  const auto cashaddr = get_param(params, "cashaddrPrefix");

  if (address.find(':') != std::string::npos) return validate_cashaddr(address, cashaddr);
  if (looks_like_configured_bech32(address, bech32)) return validate_bech32(address, bech32);
  if (looks_like_cashaddr_plain(address) && !cashaddr.empty()) return validate_cashaddr(address, cashaddr);
  return validate_base58(address, p2pkh, p2sh);
}

std::vector<AddressVariantResult> address_variants_from_legacy(const std::map<std::string, std::string>& params) {
  const auto address = trim_address(get_param(params, "address"));
  if (get_param(params, "addressType") == "p2wpkh") {
    const auto validated = validate_address({
      {"address", address},
      {"bech32Hrp", get_param(params, "bech32Hrp")},
      {"addressType", "p2wpkh"},
    });
    if (!validated.is_valid || validated.script_kind != "p2wpkh") {
      throw std::runtime_error(validated.error.empty() ? "invalid segwit address" : validated.error);
    }
    return {{"bech32", "Bech32", address, "p2wpkh", false}};
  }
  if (get_param(params, "addressType") == "p2tr") {
    const auto validated = validate_address({
      {"address", address},
      {"bech32Hrp", get_param(params, "bech32Hrp")},
      {"addressType", "p2tr"},
    });
    if (!validated.is_valid || validated.script_kind != "p2tr") {
      throw std::runtime_error(validated.error.empty() ? "invalid taproot address" : validated.error);
    }
    return {{"bech32", "Taproot", address, "p2tr", false}};
  }

  const int p2pkh = to_int(params, "p2pkhPrefix");
  const int p2sh = to_int(params, "p2shPrefix");
  const auto bech32 = get_param(params, "bech32Hrp");
  const auto cashaddr = get_param(params, "cashaddrPrefix");
  std::string error;
  const auto payload = base58check_payload(address, error);
  if (!payload || payload->size() != 21) throw std::runtime_error(error.empty() ? "invalid legacy address" : error);

  const int version = (*payload)[0];
  if (version != p2pkh && version != p2sh) throw std::runtime_error("wrong address prefix");
  const std::vector<uint8_t> hash(payload->begin() + 1, payload->end());
  const auto legacy_kind = version == p2sh ? "p2sh" : "p2pkh";

  std::vector<AddressVariantResult> variants{
    {"legacy", "Legacy", address, legacy_kind, false},
  };

  if (!cashaddr.empty()) {
    const auto full = cashaddr_encode(cashaddr, version == p2sh ? 1 : 0, hash);
    const auto colon = full.find(':');
    variants.push_back({"cashaddr", "CashAddr", full, legacy_kind, true});
    variants.push_back({"cashaddr-plain", "CashAddr short", colon == std::string::npos ? full : full.substr(colon + 1), legacy_kind, true});
  }

  if (!bech32.empty() && version == p2pkh) {
    variants.push_back({"bech32", "Bech32", bech32_encode(bech32, hash), "p2wpkh", false});
  }

  return variants;
}

}  // namespace altbase
