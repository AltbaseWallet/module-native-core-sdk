#include "wallet_derivation.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

constexpr const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr const char* BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t BECH32M_CONST = 0x2bc830a3U;
constexpr uint32_t HARDENED = 0x80000000U;

using Bytes = std::vector<uint8_t>;

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
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

std::string bytes_hex(const Bytes& bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : bytes) out << std::setw(2) << static_cast<int>(byte);
  return out.str();
}

Bytes sha_digest(const wchar_t* algorithm, const Bytes& bytes, size_t output_size) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) != 0) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
  }

  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  if (BCryptCreateHash(alg, &hash_handle, nullptr, 0, nullptr, 0, 0) != 0) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash failed");
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
    throw std::runtime_error("BCryptHashData failed");
  }

  Bytes hash(output_size);
  const auto status = BCryptFinishHash(hash_handle, hash.data(), static_cast<ULONG>(hash.size()), 0);
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptFinishHash failed");
  return hash;
#else
  (void)algorithm;
  if (output_size != 32) throw std::runtime_error("unsupported digest size");
  Bytes hash(output_size);
  unsigned int len = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), hash.data(), &len, EVP_sha256(), nullptr) != 1 || len != hash.size()) {
    throw std::runtime_error("EVP_Digest failed");
  }
  return hash;
#endif
}

Bytes sha256(const Bytes& bytes) {
#ifdef _WIN32
  return sha_digest(BCRYPT_SHA256_ALGORITHM, bytes, 32);
#else
  return sha_digest(nullptr, bytes, 32);
#endif
}

Bytes hash256(const Bytes& bytes) {
  return sha256(sha256(bytes));
}

Bytes tagged_hash(const std::string& tag, const Bytes& msg) {
  const Bytes tag_bytes(tag.begin(), tag.end());
  const auto tag_hash = sha256(tag_bytes);
  Bytes data;
  data.reserve(tag_hash.size() * 2 + msg.size());
  data.insert(data.end(), tag_hash.begin(), tag_hash.end());
  data.insert(data.end(), tag_hash.begin(), tag_hash.end());
  data.insert(data.end(), msg.begin(), msg.end());
  return sha256(data);
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

std::vector<uint8_t> convert_bits(const Bytes& data, int from_bits, int to_bits, bool pad) {
  int acc = 0;
  int bits = 0;
  const int maxv = (1 << to_bits) - 1;
  std::vector<uint8_t> out;
  for (const auto value : data) {
    if ((value >> from_bits) != 0) throw std::runtime_error("invalid bech32 data");
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
    throw std::runtime_error("invalid bech32 padding");
  }
  return out;
}

std::string bech32_encode_witness(const std::string& hrp, int witness_version, const Bytes& program) {
  if (hrp.empty()) throw std::runtime_error("bech32Hrp is required");
  if (witness_version < 0 || witness_version > 16) throw std::runtime_error("invalid witness version");

  std::string normalized = hrp;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });

  std::vector<int> data{witness_version};
  const auto converted = convert_bits(program, 8, 5, true);
  data.insert(data.end(), converted.begin(), converted.end());

  auto values = hrp_expand(normalized);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  const auto checksum_constant = witness_version == 0 ? 1U : BECH32M_CONST;
  const auto mod = bech32_polymod(values) ^ checksum_constant;

  std::string out = normalized + "1";
  for (const auto value : data) out.push_back(BECH32[static_cast<size_t>(value)]);
  for (int i = 0; i < 6; ++i) {
    out.push_back(BECH32[static_cast<size_t>((mod >> (5 * (5 - i))) & 31U)]);
  }
  return out;
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data) {
#ifdef _WIN32
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

  const auto data_status = BCryptHashData(
    hash_handle,
    const_cast<PUCHAR>(data.data()),
    static_cast<ULONG>(data.size()),
    0
  );
  if (data_status != 0) {
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
#else
  Bytes out(64);
  unsigned int len = 0;
  if (!HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &len) ||
      len != out.size()) {
    throw std::runtime_error("HMAC-SHA512 failed");
  }
  return out;
#endif
}

Bytes bip32_master_key_label() {
  Bytes label;
  label.reserve(12);
  for (const char c : {'B', 'i', 't', 'c', 'o', 'i', 'n', ' '}) {
    label.push_back(static_cast<uint8_t>(c));
  }
  label.push_back(static_cast<uint8_t>('r' + 1));
  label.push_back(static_cast<uint8_t>('d' + 1));
  label.push_back(static_cast<uint8_t>('d' + 1));
  label.push_back(static_cast<uint8_t>('c' + 1));
  return label;
}

Bytes pbkdf2_hmac_sha512(const std::string& password, const std::string& salt) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(PBKDF2) failed");
  }

  Bytes out(64);
  const auto status = BCryptDeriveKeyPBKDF2(
    alg,
    reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
    static_cast<ULONG>(password.size()),
    reinterpret_cast<PUCHAR>(const_cast<char*>(salt.data())),
    static_cast<ULONG>(salt.size()),
    2048,
    out.data(),
    static_cast<ULONG>(out.size()),
    0
  );
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed");
  return out;
#else
  Bytes out(64);
  if (PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()),
        2048,
        EVP_sha512(),
        static_cast<int>(out.size()),
        out.data()
      ) != 1) {
    throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
  }
  return out;
#endif
}

uint32_t rol(uint32_t value, int bits) {
  return (value << bits) | (value >> (32 - bits));
}

uint32_t ripemd_f(int round, uint32_t x, uint32_t y, uint32_t z) {
  if (round <= 15) return x ^ y ^ z;
  if (round <= 31) return (x & y) | (~x & z);
  if (round <= 47) return (x | ~y) ^ z;
  if (round <= 63) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

uint32_t ripemd_k(int round) {
  if (round <= 15) return 0x00000000U;
  if (round <= 31) return 0x5a827999U;
  if (round <= 47) return 0x6ed9eba1U;
  if (round <= 63) return 0x8f1bbcdcU;
  return 0xa953fd4eU;
}

uint32_t ripemd_kk(int round) {
  if (round <= 15) return 0x50a28be6U;
  if (round <= 31) return 0x5c4dd124U;
  if (round <= 47) return 0x6d703ef3U;
  if (round <= 63) return 0x7a6d76e9U;
  return 0x00000000U;
}

Bytes ripemd160(const Bytes& input) {
  static constexpr std::array<int, 80> r = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
  };
  static constexpr std::array<int, 80> rr = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
  };
  static constexpr std::array<int, 80> s = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
  };
  static constexpr std::array<int, 80> ss = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
  };

  Bytes msg = input;
  const uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8U;
  msg.push_back(0x80);
  while ((msg.size() % 64) != 56) msg.push_back(0);
  for (int i = 0; i < 8; ++i) msg.push_back(static_cast<uint8_t>((bit_len >> (8 * i)) & 0xffU));

  uint32_t h0 = 0x67452301U;
  uint32_t h1 = 0xefcdab89U;
  uint32_t h2 = 0x98badcfeU;
  uint32_t h3 = 0x10325476U;
  uint32_t h4 = 0xc3d2e1f0U;

  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    std::array<uint32_t, 16> x{};
    for (size_t i = 0; i < 16; ++i) {
      const size_t j = offset + i * 4;
      x[i] = static_cast<uint32_t>(msg[j]) |
             (static_cast<uint32_t>(msg[j + 1]) << 8U) |
             (static_cast<uint32_t>(msg[j + 2]) << 16U) |
             (static_cast<uint32_t>(msg[j + 3]) << 24U);
    }

    uint32_t al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    uint32_t ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (int i = 0; i < 80; ++i) {
      const uint32_t tl = rol(al + ripemd_f(i, bl, cl, dl) + x[static_cast<size_t>(r[static_cast<size_t>(i)])] + ripemd_k(i), s[static_cast<size_t>(i)]) + el;
      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = tl;

      const uint32_t tr = rol(ar + ripemd_f(79 - i, br, cr, dr) + x[static_cast<size_t>(rr[static_cast<size_t>(i)])] + ripemd_kk(i), ss[static_cast<size_t>(i)]) + er;
      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = tr;
    }

    const uint32_t t = h1 + cl + dr;
    h1 = h2 + dl + er;
    h2 = h3 + el + ar;
    h3 = h4 + al + br;
    h4 = h0 + bl + cr;
    h0 = t;
  }

  Bytes out;
  out.reserve(20);
  for (const auto word : {h0, h1, h2, h3, h4}) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((word >> (8 * i)) & 0xffU));
  }
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

std::vector<uint32_t> parse_path(const std::string& path) {
  if (path.size() < 2 || path[0] != 'm' || path[1] != '/') {
    throw std::runtime_error("invalid derivation path");
  }
  std::vector<uint32_t> out;
  size_t start = 2;
  while (start < path.size()) {
    size_t end = path.find('/', start);
    if (end == std::string::npos) end = path.size();
    std::string part = path.substr(start, end - start);
    const bool hardened = !part.empty() && (part.back() == '\'' || part.back() == 'h' || part.back() == 'H');
    if (hardened) part.pop_back();
    if (part.empty() || !std::all_of(part.begin(), part.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) {
      throw std::runtime_error("invalid derivation path segment");
    }
    const auto value = static_cast<uint32_t>(std::stoul(part));
    if (value >= HARDENED) throw std::runtime_error("derivation path index out of range");
    out.push_back(hardened ? value + HARDENED : value);
    start = end + 1;
  }
  return out;
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

Bytes taproot_output_key(secp256k1_context* ctx, const Bytes& compressed_public_key) {
  secp256k1_pubkey pubkey;
  if (compressed_public_key.size() != 33 ||
      secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_public_key.data(), compressed_public_key.size()) != 1) {
    throw std::runtime_error("invalid taproot public key");
  }

  secp256k1_xonly_pubkey internal_xonly;
  int parity = 0;
  if (secp256k1_xonly_pubkey_from_pubkey(ctx, &internal_xonly, &parity, &pubkey) != 1) {
    throw std::runtime_error("taproot x-only conversion failed");
  }

  Bytes internal(32);
  if (secp256k1_xonly_pubkey_serialize(ctx, internal.data(), &internal_xonly) != 1) {
    throw std::runtime_error("taproot x-only encode failed");
  }

  const auto tweak = tagged_hash("TapTweak", internal);
  secp256k1_pubkey output_pubkey;
  if (secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &internal_xonly, tweak.data()) != 1) {
    throw std::runtime_error("taproot tweak failed");
  }

  secp256k1_xonly_pubkey output_xonly;
  if (secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, &parity, &output_pubkey) != 1) {
    throw std::runtime_error("taproot output conversion failed");
  }

  Bytes out(32);
  if (secp256k1_xonly_pubkey_serialize(ctx, out.data(), &output_xonly) != 1) {
    throw std::runtime_error("taproot output encode failed");
  }
  return out;
}

Bytes derive_private_key(const std::string& mnemonic, const std::string& path, Bytes& public_key) {
  constexpr std::array<char, 8> bip39_salt = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
  const auto seed = pbkdf2_hmac_sha512(mnemonic, std::string(bip39_salt.begin(), bip39_salt.end()));
  const auto master = hmac_sha512(bip32_master_key_label(), seed);
  Bytes private_key(master.begin(), master.begin() + 32);
  Bytes chain_code(master.begin() + 32, master.end());

  std::unique_ptr<secp256k1_context, SecpContextDeleter> ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE));
  if (!ctx || secp256k1_ec_seckey_verify(ctx.get(), private_key.data()) != 1) {
    throw std::runtime_error("wallet key derivation failed");
  }

  for (const auto index : parse_path(path)) {
    Bytes data;
    if ((index & HARDENED) != 0U) {
      data.push_back(0);
      data.insert(data.end(), private_key.begin(), private_key.end());
    } else {
      const auto pub = public_key_compressed(ctx.get(), private_key);
      data.insert(data.end(), pub.begin(), pub.end());
    }
    const auto index_bytes = ser32(index);
    data.insert(data.end(), index_bytes.begin(), index_bytes.end());

    const auto child = hmac_sha512(chain_code, data);
    Bytes tweak(child.begin(), child.begin() + 32);
    if (secp256k1_ec_seckey_verify(ctx.get(), tweak.data()) != 1 ||
        secp256k1_ec_seckey_tweak_add(ctx.get(), private_key.data(), tweak.data()) != 1) {
      throw std::runtime_error("wallet key derivation failed");
    }
    chain_code.assign(child.begin() + 32, child.end());
  }

  public_key = public_key_compressed(ctx.get(), private_key);
  return private_key;
}

}  // namespace

WalletKeyMaterial derive_wallet_key_material(const std::string& mnemonic, const std::string& derivation_path) {
  Bytes public_key;
  const auto private_key = derive_private_key(mnemonic, derivation_path, public_key);
  return {private_key, public_key};
}

WalletDerivationResult derive_wallet_material(const std::map<std::string, std::string>& params) {
  const auto mnemonic = get_param(params, "phrase");
  const auto path = get_param(params, "derivationPath");
  const auto address_type = get_param(params, "addressType");
  const int p2pkh = to_int(params, "p2pkhPrefix");
  const int wif = to_int(params, "wifPrefix");
  if (mnemonic.empty()) throw std::runtime_error("wallet phrase is required");
  if (path.empty()) throw std::runtime_error("derivationPath is required");
  if (address_type != "p2tr" && (p2pkh < 0 || p2pkh > 255)) throw std::runtime_error("p2pkhPrefix is required");
  if (wif < 0 || wif > 255) throw std::runtime_error("wifPrefix is required");

  const auto key_material = derive_wallet_key_material(mnemonic, path);
  const auto& private_key = key_material.private_key;
  const auto& public_key = key_material.public_key;
  Bytes wif_payload{static_cast<uint8_t>(wif)};
  wif_payload.insert(wif_payload.end(), private_key.begin(), private_key.end());
  wif_payload.push_back(0x01);
  const auto private_key_wif = base58check_text(wif_payload);

  if (address_type == "p2tr") {
    std::unique_ptr<secp256k1_context, SecpContextDeleter> ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE));
    if (!ctx) throw std::runtime_error("secp256k1 context creation failed");
    const auto output_key = taproot_output_key(ctx.get(), public_key);
    return {
      bech32_encode_witness(get_param(params, "bech32Hrp"), 1, output_key),
      private_key_wif,
      bytes_hex(public_key),
    };
  }

  const auto public_key_hash = ripemd160(sha256(public_key));

  if (address_type == "p2wpkh") {
    return {
      bech32_encode_witness(get_param(params, "bech32Hrp"), 0, public_key_hash),
      private_key_wif,
      bytes_hex(public_key),
    };
  }

  Bytes address_payload{static_cast<uint8_t>(p2pkh)};
  address_payload.insert(address_payload.end(), public_key_hash.begin(), public_key_hash.end());

  return {
    base58check_text(address_payload),
    private_key_wif,
    bytes_hex(public_key),
  };
}

}  // namespace altbase
