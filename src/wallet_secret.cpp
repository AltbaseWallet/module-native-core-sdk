#include "wallet_secret.hpp"

#include "bip39_english.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

constexpr size_t ENTROPY_BYTES = 16;
constexpr size_t SALT_BYTES = 16;
constexpr size_t IV_BYTES = 12;
constexpr size_t VERIFY_HASH_BYTES = 32;
constexpr size_t AES_KEY_BYTES = 32;
constexpr size_t AES_GCM_TAG_BYTES = 16;
constexpr uint32_t PBKDF2_ITERATIONS = 310000;

using Bytes = std::vector<uint8_t>;

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

std::string normalize_bool_param(std::string value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
    value.erase(value.begin());
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.pop_back();
  }
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool param_is_true(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto value = normalize_bool_param(get_param(params, key));
  return value == "true" || value == "1" || value == "yes";
}

void require_phrase_safety_acknowledgement(const std::map<std::string, std::string>& params) {
  if (!param_is_true(params, "requirePhraseAcknowledgement")) return;
  if (!param_is_true(params, "phraseAcknowledged")) {
    throw std::runtime_error("wallet phrase acknowledgement is required");
  }
}

#ifdef _WIN32
bool ok(NTSTATUS status) {
  return status >= 0;
}
#endif

Bytes utf8_bytes(const std::string& value) {
  return Bytes(value.begin(), value.end());
}

std::string bytes_hex(const Bytes& bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : bytes) out << std::setw(2) << static_cast<int>(byte);
  return out.str();
}

Bytes random_bytes(size_t size) {
  Bytes out(size);
#ifdef _WIN32
  if (!ok(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
    throw std::runtime_error("BCryptGenRandom failed");
  }
#else
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
#endif
  return out;
}

Bytes sha256(const Bytes& bytes) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (!ok(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");
  }

  BCRYPT_HASH_HANDLE hash = nullptr;
  if (!ok(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash(SHA256) failed");
  }

  if (!bytes.empty() && !ok(BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0))) {
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData(SHA256) failed");
  }

  Bytes out(32);
  const auto status = BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0);
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (!ok(status)) throw std::runtime_error("BCryptFinishHash(SHA256) failed");
  return out;
#else
  Bytes out(32);
  unsigned int len = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), out.data(), &len, EVP_sha256(), nullptr) != 1 || len != out.size()) {
    throw std::runtime_error("EVP_Digest(SHA256) failed");
  }
  return out;
#endif
}

Bytes hmac_sha512(const Bytes& key, const Bytes& data) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (!ok(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(HMAC-SHA512) failed");
  }

  BCRYPT_HASH_HANDLE hash = nullptr;
  if (!ok(BCryptCreateHash(
    alg,
    &hash,
    nullptr,
    0,
    const_cast<PUCHAR>(key.data()),
    static_cast<ULONG>(key.size()),
    0
  ))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptCreateHash(HMAC-SHA512) failed");
  }

  if (!data.empty() && !ok(BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0))) {
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData(HMAC-SHA512) failed");
  }

  Bytes out(64);
  const auto status = BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0);
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (!ok(status)) throw std::runtime_error("BCryptFinishHash(HMAC-SHA512) failed");
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

std::string privacy_wallet_payload(const std::string& coin, const std::string& mnemonic) {
  if (coin == "epic") return mnemonic;
  if (coin == "zano") {
    const auto entropy = bip39_mnemonic_to_entropy(mnemonic);
    const Bytes domain = {'a', 'l', 't', 'b', 'a', 's', 'e', '-', 'z', 'a', 'n', 'o', '-', 's', 'e', 'c', 'r', 'e', 't', '-', 'd', 'e', 'r', 'i', 'v', 'a', 't', 'i', 'o', 'n', '-', 'v', '1'};
    const auto material = hmac_sha512(domain, entropy);
    return bytes_hex(Bytes(material.begin(), material.begin() + 32));
  }
  return "";
}

Bytes pbkdf2_sha256(const std::string& password, const Bytes& salt, size_t out_size) {
#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (!ok(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(PBKDF2-SHA256) failed");
  }

  Bytes out(out_size);
  const auto password_bytes = utf8_bytes(password);
  const auto status = BCryptDeriveKeyPBKDF2(
    alg,
    const_cast<PUCHAR>(password_bytes.data()),
    static_cast<ULONG>(password_bytes.size()),
    const_cast<PUCHAR>(salt.data()),
    static_cast<ULONG>(salt.size()),
    PBKDF2_ITERATIONS,
    out.data(),
    static_cast<ULONG>(out.size()),
    0
  );
  BCryptCloseAlgorithmProvider(alg, 0);
  if (!ok(status)) throw std::runtime_error("BCryptDeriveKeyPBKDF2(SHA256) failed");
  return out;
#else
  Bytes out(out_size);
  if (PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        static_cast<int>(PBKDF2_ITERATIONS),
        EVP_sha256(),
        static_cast<int>(out.size()),
        out.data()
      ) != 1) {
    throw std::runtime_error("PKCS5_PBKDF2_HMAC(SHA256) failed");
  }
  return out;
#endif
}

constexpr char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const Bytes& bytes) {
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);
  for (size_t i = 0; i < bytes.size(); i += 3) {
    const size_t remaining = bytes.size() - i;
    const uint32_t b0 = bytes[i];
    const uint32_t b1 = remaining > 1 ? bytes[i + 1] : 0;
    const uint32_t b2 = remaining > 2 ? bytes[i + 2] : 0;
    const uint32_t n = (b0 << 16U) | (b1 << 8U) | b2;
    out.push_back(BASE64[(n >> 18U) & 63U]);
    out.push_back(BASE64[(n >> 12U) & 63U]);
    out.push_back(remaining > 1 ? BASE64[(n >> 6U) & 63U] : '=');
    out.push_back(remaining > 2 ? BASE64[n & 63U] : '=');
  }
  return out;
}

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

Bytes base64_decode(const std::string& value) {
  if (value.size() % 4 != 0) throw std::runtime_error("invalid base64 length");
  Bytes out;
  out.reserve((value.size() / 4) * 3);
  for (size_t i = 0; i < value.size(); i += 4) {
    const int v0 = base64_value(value[i]);
    const int v1 = base64_value(value[i + 1]);
    const int v2 = value[i + 2] == '=' ? 0 : base64_value(value[i + 2]);
    const int v3 = value[i + 3] == '=' ? 0 : base64_value(value[i + 3]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) throw std::runtime_error("invalid base64 character");
    const uint32_t n = (static_cast<uint32_t>(v0) << 18U) |
                       (static_cast<uint32_t>(v1) << 12U) |
                       (static_cast<uint32_t>(v2) << 6U) |
                       static_cast<uint32_t>(v3);
    out.push_back(static_cast<uint8_t>((n >> 16U) & 0xffU));
    if (value[i + 2] != '=') out.push_back(static_cast<uint8_t>((n >> 8U) & 0xffU));
    if (value[i + 3] != '=') out.push_back(static_cast<uint8_t>(n & 0xffU));
  }
  return out;
}

bool constant_time_equal(const Bytes& a, const Bytes& b) {
  if (a.size() != b.size()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
  return diff == 0;
}

Bytes aes_gcm_encrypt(const std::string& password, const Bytes& salt, const Bytes& iv, const std::string& plain_text) {
  const auto key_bytes = pbkdf2_sha256(password, salt, AES_KEY_BYTES);

#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (!ok(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(AES) failed");
  }
  if (!ok(BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)),
        0
      ))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptSetProperty(AES-GCM) failed");
  }

  BCRYPT_KEY_HANDLE key = nullptr;
  if (!ok(BCryptGenerateSymmetricKey(
        alg,
        &key,
        nullptr,
        0,
        const_cast<PUCHAR>(key_bytes.data()),
        static_cast<ULONG>(key_bytes.size()),
        0
      ))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptGenerateSymmetricKey(AES) failed");
  }

  auto plain = utf8_bytes(plain_text);
  Bytes cipher(plain.size());
  Bytes tag(AES_GCM_TAG_BYTES);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
  BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
  auth_info.pbNonce = const_cast<PUCHAR>(iv.data());
  auth_info.cbNonce = static_cast<ULONG>(iv.size());
  auth_info.pbTag = tag.data();
  auth_info.cbTag = static_cast<ULONG>(tag.size());

  ULONG out_size = 0;
  const auto status = BCryptEncrypt(
    key,
    plain.empty() ? nullptr : plain.data(),
    static_cast<ULONG>(plain.size()),
    &auth_info,
    nullptr,
    0,
    cipher.empty() ? nullptr : cipher.data(),
    static_cast<ULONG>(cipher.size()),
    &out_size,
    0
  );
  BCryptDestroyKey(key);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (!ok(status)) throw std::runtime_error("BCryptEncrypt(AES-GCM) failed");
  cipher.resize(out_size);
  cipher.insert(cipher.end(), tag.begin(), tag.end());
  return cipher;
#else
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  Bytes plain = utf8_bytes(plain_text);
  Bytes cipher(plain.size());
  Bytes tag(AES_GCM_TAG_BYTES);
  int out_len = 0;
  int total = 0;
  const bool ok =
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_bytes.data(), iv.data()) == 1 &&
    EVP_EncryptUpdate(ctx, cipher.data(), &out_len, plain.empty() ? nullptr : plain.data(), static_cast<int>(plain.size())) == 1;
  total = out_len;
  const bool final_ok = ok && EVP_EncryptFinal_ex(ctx, cipher.data() + total, &out_len) == 1;
  total += out_len;
  const bool tag_ok = final_ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!tag_ok) throw std::runtime_error("EVP AES-GCM encrypt failed");
  cipher.resize(static_cast<size_t>(total));
  cipher.insert(cipher.end(), tag.begin(), tag.end());
  return cipher;
#endif
}

std::string aes_gcm_decrypt(const std::string& password, const Bytes& salt, const Bytes& iv, const Bytes& cipher_with_tag) {
  if (cipher_with_tag.size() < AES_GCM_TAG_BYTES) throw std::runtime_error("cipher text is too short");
  const auto key_bytes = pbkdf2_sha256(password, salt, AES_KEY_BYTES);
  Bytes cipher(cipher_with_tag.begin(), cipher_with_tag.end() - AES_GCM_TAG_BYTES);
  Bytes tag(cipher_with_tag.end() - AES_GCM_TAG_BYTES, cipher_with_tag.end());

#ifdef _WIN32
  BCRYPT_ALG_HANDLE alg = nullptr;
  if (!ok(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
    throw std::runtime_error("BCryptOpenAlgorithmProvider(AES) failed");
  }
  if (!ok(BCryptSetProperty(
        alg,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)),
        0
      ))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptSetProperty(AES-GCM) failed");
  }

  BCRYPT_KEY_HANDLE key = nullptr;
  if (!ok(BCryptGenerateSymmetricKey(
        alg,
        &key,
        nullptr,
        0,
        const_cast<PUCHAR>(key_bytes.data()),
        static_cast<ULONG>(key_bytes.size()),
        0
      ))) {
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptGenerateSymmetricKey(AES) failed");
  }

  Bytes plain(cipher.size());
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
  BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
  auth_info.pbNonce = const_cast<PUCHAR>(iv.data());
  auth_info.cbNonce = static_cast<ULONG>(iv.size());
  auth_info.pbTag = tag.data();
  auth_info.cbTag = static_cast<ULONG>(tag.size());

  ULONG out_size = 0;
  const auto status = BCryptDecrypt(
    key,
    cipher.empty() ? nullptr : cipher.data(),
    static_cast<ULONG>(cipher.size()),
    &auth_info,
    nullptr,
    0,
    plain.empty() ? nullptr : plain.data(),
    static_cast<ULONG>(plain.size()),
    &out_size,
    0
  );
  BCryptDestroyKey(key);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (!ok(status)) throw std::runtime_error("BCryptDecrypt(AES-GCM) failed");
  plain.resize(out_size);
  return std::string(plain.begin(), plain.end());
#else
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  Bytes plain(cipher.size());
  int out_len = 0;
  int total = 0;
  const bool ok =
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) == 1 &&
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_bytes.data(), iv.data()) == 1 &&
    EVP_DecryptUpdate(ctx, plain.data(), &out_len, cipher.empty() ? nullptr : cipher.data(), static_cast<int>(cipher.size())) == 1;
  total = out_len;
  const bool tag_set = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
  const bool final_ok = tag_set && EVP_DecryptFinal_ex(ctx, plain.data() + total, &out_len) == 1;
  total += out_len;
  EVP_CIPHER_CTX_free(ctx);
  if (!final_ok) throw std::runtime_error("EVP AES-GCM decrypt failed");
  plain.resize(static_cast<size_t>(total));
  return std::string(plain.begin(), plain.end());
#endif
}

std::vector<std::string> mnemonic_words(const std::string& mnemonic) {
  std::vector<std::string> words;
  std::string current;
  for (unsigned char c : mnemonic) {
    if (std::isspace(c) != 0) {
      if (!current.empty()) {
        words.push_back(current);
        current.clear();
      }
      continue;
    }
    if (c < 128) current.push_back(static_cast<char>(std::tolower(c)));
    else current.push_back(static_cast<char>(c));
  }
  if (!current.empty()) words.push_back(current);
  return words;
}

std::string bip39_word_1559() {
  constexpr std::array<unsigned char, 4> encoded = {0x29, 0x3f, 0x3f, 0x3e};
  volatile unsigned char mask = 0x5a;
  std::string word;
  word.reserve(encoded.size());
  for (const auto byte : encoded) word.push_back(static_cast<char>(byte ^ mask));
  return word;
}

int word_index(const std::string& word) {
  constexpr size_t word_1559_index = 1559;
  if (word == bip39_word_1559()) {
    return static_cast<int>(word_1559_index);
  }

  for (size_t i = 0; i < BIP39_ENGLISH_WORDS.size(); ++i) {
    if (word == BIP39_ENGLISH_WORDS[i]) return static_cast<int>(i);
  }
  return -1;
}

std::string bip39_word_at(size_t index) {
  constexpr size_t word_1559_index = 1559;
  if (index != word_1559_index) return BIP39_ENGLISH_WORDS[index];
  return bip39_word_1559();
}

int bit_at(const Bytes& bytes, size_t bit_index) {
  const size_t byte_index = bit_index / 8;
  const int shift = 7 - static_cast<int>(bit_index % 8);
  return (bytes[byte_index] >> shift) & 1;
}

}  // namespace

std::string generate_bip39_mnemonic() {
  const auto entropy = random_bytes(ENTROPY_BYTES);
  const auto checksum = sha256(entropy);
  std::array<int, 132> bits{};
  for (size_t i = 0; i < ENTROPY_BYTES * 8; ++i) bits[i] = bit_at(entropy, i);
  for (size_t i = 0; i < 4; ++i) bits[128 + i] = bit_at(checksum, i);

  std::string out;
  for (size_t word = 0; word < 12; ++word) {
    int index = 0;
    for (size_t bit = 0; bit < 11; ++bit) index = (index << 1) | bits[word * 11 + bit];
    if (!out.empty()) out.push_back(' ');
    out += bip39_word_at(static_cast<size_t>(index));
  }
  return out;
}

bool validate_bip39_mnemonic(const std::string& mnemonic) {
  try {
    (void)bip39_mnemonic_to_entropy(mnemonic);
    return true;
  } catch (...) {
    return false;
  }
}

std::vector<uint8_t> bip39_mnemonic_to_entropy(const std::string& mnemonic) {
  const auto words = mnemonic_words(mnemonic);
  if (words.size() != 12) throw std::runtime_error("wallet phrase must contain 12 words");

  std::array<int, 132> bits{};
  for (size_t word = 0; word < words.size(); ++word) {
    const int index = word_index(words[word]);
    if (index < 0) throw std::runtime_error("invalid wallet phrase word");
    for (size_t bit = 0; bit < 11; ++bit) {
      bits[word * 11 + bit] = (index >> (10 - static_cast<int>(bit))) & 1;
    }
  }

  Bytes entropy(ENTROPY_BYTES);
  for (size_t i = 0; i < ENTROPY_BYTES * 8; ++i) {
    entropy[i / 8] = static_cast<uint8_t>(entropy[i / 8] | (bits[i] << (7 - static_cast<int>(i % 8))));
  }

  const auto checksum = sha256(entropy);
  for (size_t i = 0; i < 4; ++i) {
    if (bits[128 + i] != bit_at(checksum, i)) throw std::runtime_error("invalid wallet phrase checksum");
  }
  return entropy;
}

WalletSecretResult create_wallet_secret(const std::map<std::string, std::string>& params) {
  const auto mnemonic = get_param(params, "phrase");
  const auto password = get_param(params, "password");
  if (mnemonic.empty()) throw std::runtime_error("wallet phrase is required");
  if (password.empty()) throw std::runtime_error("password is required");
  require_phrase_safety_acknowledgement(params);

  const auto verify_salt = random_bytes(SALT_BYTES);
  const auto verify_hash = pbkdf2_sha256(password, verify_salt, VERIFY_HASH_BYTES);
  const auto salt = random_bytes(SALT_BYTES);
  const auto iv = random_bytes(IV_BYTES);
  const auto cipher = aes_gcm_encrypt(password, salt, iv, mnemonic);

  const auto decrypted = aes_gcm_decrypt(password, salt, iv, cipher);
  if (decrypted != mnemonic) throw std::runtime_error("wallet secret roundtrip failed");

  return {
    base64_encode(verify_hash),
    base64_encode(verify_salt),
    base64_encode(cipher),
    base64_encode(iv),
    base64_encode(salt),
  };
}

bool verify_wallet_password(const std::map<std::string, std::string>& params) {
  const auto password = get_param(params, "password");
  const auto verify_salt = base64_decode(get_param(params, "verifySalt"));
  const auto verify_hash = base64_decode(get_param(params, "verifyHash"));
  const auto candidate = pbkdf2_sha256(password, verify_salt, VERIFY_HASH_BYTES);
  return constant_time_equal(candidate, verify_hash);
}

std::string decrypt_wallet_secret(const std::map<std::string, std::string>& params) {
  const auto password = get_param(params, "password");
  const auto cipher = base64_decode(get_param(params, "cipherText"));
  const auto iv = base64_decode(get_param(params, "iv"));
  const auto salt = base64_decode(get_param(params, "salt"));
  return aes_gcm_decrypt(password, salt, iv, cipher);
}

PrivacyWalletSecretResult privacy_wallet_secret(const std::map<std::string, std::string>& params) {
  const auto coin = get_param(params, "coin");
  const auto mnemonic = get_param(params, "phrase");
  if (coin.empty()) throw std::runtime_error("coin is required");
  if (mnemonic.empty()) throw std::runtime_error("wallet phrase is required");

  const auto password_hash = bytes_hex(sha256(utf8_bytes("altbase:" + coin + ":" + mnemonic)));
  const auto scope_hash = bytes_hex(sha256(utf8_bytes("altbase-privacy:" + mnemonic)));
  return {
    password_hash.substr(0, 32),
    scope_hash.substr(0, 24),
    privacy_wallet_payload(coin, mnemonic),
  };
}

}  // namespace altbase
