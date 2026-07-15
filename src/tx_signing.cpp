#include "tx_signing.hpp"

#include "wallet_derivation.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint32_t DEFAULT_TX_VERSION = 1;
constexpr uint32_t SEQUENCE = 0xffffffffU;
constexpr uint32_t SIGHASH_ALL = 0x01U;
constexpr uint32_t SIGHASH_FORKID = 0x40U;
constexpr uint32_t SIGHASH_ALL_FORKID = SIGHASH_ALL | SIGHASH_FORKID;

struct TxIn {
  std::string txid;
  uint32_t vout = 0;
  uint64_t value = 0;
  Bytes script_sig;
  Bytes prev_script;
  std::vector<Bytes> witness;
  uint32_t sequence = SEQUENCE;
};

struct TxOut {
  uint64_t value = 0;
  Bytes script;
};

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

uint32_t parse_tx_version(const std::map<std::string, std::string>& params) {
  const auto raw = get_param(params, "txVersion");
  if (raw.empty()) return DEFAULT_TX_VERSION;

  size_t consumed = 0;
  const auto version = std::stoul(raw, &consumed, 10);
  if (consumed != raw.size() || version < 1 || version > 3) {
    throw std::runtime_error("invalid txVersion");
  }
  return static_cast<uint32_t>(version);
}

std::vector<std::string> split(const std::string& value, char delimiter) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= value.size()) {
    const auto pos = value.find(delimiter, start);
    if (pos == std::string::npos) {
      out.push_back(value.substr(start));
      break;
    }
    out.push_back(value.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

uint8_t hex_value(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
  throw std::runtime_error("invalid hex character");
}

Bytes from_hex(std::string hex) {
  if (hex.size() % 2 != 0) hex = "0" + hex;
  Bytes out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>((hex_value(hex[i]) << 4U) | hex_value(hex[i + 1])));
  }
  return out;
}

std::string to_hex(const Bytes& bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : bytes) out << std::setw(2) << static_cast<int>(byte);
  return out.str();
}

void append(Bytes& out, const Bytes& bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

Bytes concat(const std::vector<Bytes>& parts) {
  Bytes out;
  size_t total = 0;
  for (const auto& part : parts) total += part.size();
  out.reserve(total);
  for (const auto& part : parts) append(out, part);
  return out;
}

Bytes u32le(uint32_t value) {
  return Bytes{
    static_cast<uint8_t>(value & 0xffU),
    static_cast<uint8_t>((value >> 8U) & 0xffU),
    static_cast<uint8_t>((value >> 16U) & 0xffU),
    static_cast<uint8_t>((value >> 24U) & 0xffU),
  };
}

Bytes u64le(uint64_t value) {
  Bytes out(8);
  for (int i = 0; i < 8; ++i) out[static_cast<size_t>(i)] = static_cast<uint8_t>((value >> (8 * i)) & 0xffU);
  return out;
}

Bytes varint(uint64_t value) {
  if (value < 0xfdU) return Bytes{static_cast<uint8_t>(value)};
  if (value <= 0xffffU) return Bytes{0xfd, static_cast<uint8_t>(value & 0xffU), static_cast<uint8_t>((value >> 8U) & 0xffU)};
  if (value <= 0xffffffffULL) {
    Bytes out{0xfe};
    append(out, u32le(static_cast<uint32_t>(value)));
    return out;
  }
  Bytes out{0xff};
  append(out, u64le(value));
  return out;
}

Bytes sha256(const Bytes& bytes) {
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

  if (BCryptHashData(hash_handle, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) != 0) {
    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    throw std::runtime_error("BCryptHashData(SHA256) failed");
  }

  Bytes out(32);
  const auto status = BCryptFinishHash(hash_handle, out.data(), static_cast<ULONG>(out.size()), 0);
  BCryptDestroyHash(hash_handle);
  BCryptCloseAlgorithmProvider(alg, 0);
  if (status != 0) throw std::runtime_error("BCryptFinishHash(SHA256) failed");
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

Bytes hash256(const Bytes& bytes) {
  return sha256(sha256(bytes));
}

Bytes tagged_hash(const std::string& tag, const Bytes& msg) {
  const Bytes tag_bytes(tag.begin(), tag.end());
  const auto tag_hash = sha256(tag_bytes);
  Bytes data;
  data.reserve(tag_hash.size() * 2 + msg.size());
  append(data, tag_hash);
  append(data, tag_hash);
  append(data, msg);
  return sha256(data);
}

Bytes reversed_txid(const std::string& txid) {
  auto bytes = from_hex(txid);
  if (bytes.size() != 32) throw std::runtime_error("txid must be 32 bytes");
  std::reverse(bytes.begin(), bytes.end());
  return bytes;
}

Bytes serialize_input(const TxIn& input) {
  Bytes out;
  append(out, reversed_txid(input.txid));
  append(out, u32le(input.vout));
  append(out, varint(input.script_sig.size()));
  append(out, input.script_sig);
  append(out, u32le(input.sequence));
  return out;
}

Bytes serialize_output(const TxOut& output) {
  Bytes out;
  append(out, u64le(output.value));
  append(out, varint(output.script.size()));
  append(out, output.script);
  return out;
}

Bytes serialize_witness(const std::vector<Bytes>& witness) {
  Bytes out;
  append(out, varint(witness.size()));
  for (const auto& item : witness) {
    append(out, varint(item.size()));
    append(out, item);
  }
  return out;
}

Bytes serialize_tx(const std::vector<TxIn>& inputs, const std::vector<TxOut>& outputs, bool include_witness, uint32_t tx_version) {
  Bytes out;
  append(out, u32le(tx_version));
  if (include_witness) append(out, Bytes{0x00, 0x01});
  append(out, varint(inputs.size()));
  for (const auto& input : inputs) append(out, serialize_input(input));
  append(out, varint(outputs.size()));
  for (const auto& output : outputs) append(out, serialize_output(output));
  if (include_witness) {
    for (const auto& input : inputs) append(out, serialize_witness(input.witness));
  }
  append(out, u32le(0));
  return out;
}

Bytes p2pkh_script(const Bytes& hash) {
  if (hash.size() != 20) throw std::runtime_error("p2pkh hash must be 20 bytes");
  Bytes out{0x76, 0xa9, 0x14};
  append(out, hash);
  append(out, Bytes{0x88, 0xac});
  return out;
}

bool is_p2wpkh_script(const Bytes& script) {
  return script.size() == 22 && script[0] == 0x00 && script[1] == 0x14;
}

bool is_p2tr_script(const Bytes& script) {
  return script.size() == 34 && script[0] == 0x51 && script[1] == 0x20;
}

struct SecpContextDeleter {
  void operator()(secp256k1_context* ctx) const {
    secp256k1_context_destroy(ctx);
  }
};

Bytes sign_der_with_type(secp256k1_context* ctx, const Bytes& hash, const Bytes& private_key, uint32_t sighash_type) {
  if (hash.size() != 32 || private_key.size() != 32) throw std::runtime_error("invalid signing material");

  secp256k1_ecdsa_signature sig;
  if (secp256k1_ecdsa_sign(ctx, &sig, hash.data(), private_key.data(), nullptr, nullptr) != 1) {
    throw std::runtime_error("secp256k1 signing failed");
  }
  secp256k1_ecdsa_signature normalized;
  secp256k1_ecdsa_signature_normalize(ctx, &normalized, &sig);

  Bytes der(72);
  size_t der_len = der.size();
  secp256k1_ecdsa_signature_serialize_der(ctx, der.data(), &der_len, &normalized);
  der.resize(der_len);
  der.push_back(static_cast<uint8_t>(sighash_type & 0xffU));
  return der;
}

Bytes legacy_script_sig(const Bytes& der_with_type, const Bytes& public_key) {
  Bytes out;
  append(out, varint(der_with_type.size()));
  append(out, der_with_type);
  append(out, varint(public_key.size()));
  append(out, public_key);
  return out;
}

Bytes sign_input_legacy(
  secp256k1_context* ctx,
  const std::vector<TxIn>& inputs,
  const std::vector<TxOut>& outputs,
  size_t index,
  const Bytes& script_code,
  const Bytes& private_key,
  const Bytes& public_key,
  uint32_t tx_version
) {
  auto signing = inputs;
  for (size_t i = 0; i < signing.size(); ++i) signing[i].script_sig = i == index ? script_code : Bytes{};
  auto preimage = serialize_tx(signing, outputs, false, tx_version);
  append(preimage, u32le(SIGHASH_ALL));
  return legacy_script_sig(sign_der_with_type(ctx, hash256(preimage), private_key, SIGHASH_ALL), public_key);
}

Bytes sign_input_bip143_forkid(
  secp256k1_context* ctx,
  const std::vector<TxIn>& inputs,
  const std::vector<TxOut>& outputs,
  size_t index,
  const Bytes& script_code,
  const Bytes& private_key,
  const Bytes& public_key,
  uint32_t tx_version
) {
  std::vector<Bytes> prevouts_parts;
  std::vector<Bytes> sequence_parts;
  prevouts_parts.reserve(inputs.size() * 2);
  sequence_parts.reserve(inputs.size());
  for (const auto& input : inputs) {
    prevouts_parts.push_back(reversed_txid(input.txid));
    prevouts_parts.push_back(u32le(input.vout));
    sequence_parts.push_back(u32le(input.sequence));
  }

  std::vector<Bytes> output_parts;
  output_parts.reserve(outputs.size());
  for (const auto& output : outputs) output_parts.push_back(serialize_output(output));

  Bytes preimage;
  append(preimage, u32le(tx_version));
  append(preimage, hash256(concat(prevouts_parts)));
  append(preimage, hash256(concat(sequence_parts)));
  append(preimage, reversed_txid(inputs[index].txid));
  append(preimage, u32le(inputs[index].vout));
  append(preimage, varint(script_code.size()));
  append(preimage, script_code);
  append(preimage, u64le(inputs[index].value));
  append(preimage, u32le(inputs[index].sequence));
  append(preimage, hash256(concat(output_parts)));
  append(preimage, u32le(0));
  append(preimage, u32le(SIGHASH_ALL_FORKID));
  return legacy_script_sig(sign_der_with_type(ctx, hash256(preimage), private_key, SIGHASH_ALL_FORKID), public_key);
}

std::vector<Bytes> sign_input_segwit_v0(
  secp256k1_context* ctx,
  const std::vector<TxIn>& inputs,
  const std::vector<TxOut>& outputs,
  size_t index,
  const Bytes& script_code,
  const Bytes& private_key,
  const Bytes& public_key,
  uint32_t sighash_type,
  uint32_t tx_version
) {
  std::vector<Bytes> prevouts_parts;
  std::vector<Bytes> sequence_parts;
  prevouts_parts.reserve(inputs.size() * 2);
  sequence_parts.reserve(inputs.size());
  for (const auto& input : inputs) {
    prevouts_parts.push_back(reversed_txid(input.txid));
    prevouts_parts.push_back(u32le(input.vout));
    sequence_parts.push_back(u32le(input.sequence));
  }

  std::vector<Bytes> output_parts;
  output_parts.reserve(outputs.size());
  for (const auto& output : outputs) output_parts.push_back(serialize_output(output));

  Bytes preimage;
  append(preimage, u32le(tx_version));
  append(preimage, hash256(concat(prevouts_parts)));
  append(preimage, hash256(concat(sequence_parts)));
  append(preimage, reversed_txid(inputs[index].txid));
  append(preimage, u32le(inputs[index].vout));
  append(preimage, varint(script_code.size()));
  append(preimage, script_code);
  append(preimage, u64le(inputs[index].value));
  append(preimage, u32le(inputs[index].sequence));
  append(preimage, hash256(concat(output_parts)));
  append(preimage, u32le(0));
  append(preimage, u32le(sighash_type));
  return {sign_der_with_type(ctx, hash256(preimage), private_key, sighash_type), public_key};
}

Bytes serialized_outpoint(const TxIn& input) {
  Bytes out;
  append(out, reversed_txid(input.txid));
  append(out, u32le(input.vout));
  return out;
}

Bytes serialized_script_pubkey(const Bytes& script) {
  Bytes out;
  append(out, varint(script.size()));
  append(out, script);
  return out;
}

Bytes taproot_sighash(
  const std::vector<TxIn>& inputs,
  const std::vector<TxOut>& outputs,
  size_t index,
  uint32_t tx_version
) {
  std::vector<Bytes> prevouts_parts;
  std::vector<Bytes> amount_parts;
  std::vector<Bytes> script_parts;
  std::vector<Bytes> sequence_parts;
  prevouts_parts.reserve(inputs.size());
  amount_parts.reserve(inputs.size());
  script_parts.reserve(inputs.size());
  sequence_parts.reserve(inputs.size());

  for (const auto& input : inputs) {
    prevouts_parts.push_back(serialized_outpoint(input));
    amount_parts.push_back(u64le(input.value));
    script_parts.push_back(serialized_script_pubkey(input.prev_script));
    sequence_parts.push_back(u32le(input.sequence));
  }

  std::vector<Bytes> output_parts;
  output_parts.reserve(outputs.size());
  for (const auto& output : outputs) output_parts.push_back(serialize_output(output));

  Bytes msg;
  msg.push_back(0x00); // BIP341 epoch.
  msg.push_back(0x00); // SIGHASH_DEFAULT.
  append(msg, u32le(tx_version));
  append(msg, u32le(0));
  append(msg, sha256(concat(prevouts_parts)));
  append(msg, sha256(concat(amount_parts)));
  append(msg, sha256(concat(script_parts)));
  append(msg, sha256(concat(sequence_parts)));
  append(msg, sha256(concat(output_parts)));
  msg.push_back(0x00); // spend_type: key-path spend, no annex.
  append(msg, u32le(static_cast<uint32_t>(index)));

  return tagged_hash("TapSighash", msg);
}

Bytes sign_taproot_key_path(
  secp256k1_context* ctx,
  const Bytes& sighash,
  const Bytes& private_key
) {
  if (sighash.size() != 32 || private_key.size() != 32) throw std::runtime_error("invalid taproot signing material");

  secp256k1_keypair keypair;
  if (secp256k1_keypair_create(ctx, &keypair, private_key.data()) != 1) {
    throw std::runtime_error("taproot keypair creation failed");
  }

  secp256k1_pubkey pubkey;
  if (secp256k1_keypair_pub(ctx, &pubkey, &keypair) != 1) {
    throw std::runtime_error("taproot public key creation failed");
  }

  secp256k1_xonly_pubkey xonly;
  int parity = 0;
  if (secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey) != 1) {
    throw std::runtime_error("taproot x-only conversion failed");
  }

  Bytes internal(32);
  if (secp256k1_xonly_pubkey_serialize(ctx, internal.data(), &xonly) != 1) {
    throw std::runtime_error("taproot x-only encode failed");
  }

  const auto tweak = tagged_hash("TapTweak", internal);
  if (secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak.data()) != 1) {
    throw std::runtime_error("taproot key tweak failed");
  }

  Bytes sig(64);
  if (secp256k1_schnorrsig_sign32(ctx, sig.data(), sighash.data(), &keypair, nullptr) != 1) {
    throw std::runtime_error("taproot schnorr signing failed");
  }
  return sig;
}

std::vector<TxIn> parse_inputs(const std::string& encoded) {
  std::vector<TxIn> inputs;
  if (encoded.empty()) throw std::runtime_error("inputs are required");
  for (const auto& row : split(encoded, '|')) {
    if (row.empty()) continue;
    const auto parts = split(row, ':');
    if (parts.size() != 4) throw std::runtime_error("invalid input row");
    TxIn input;
    input.txid = parts[0];
    input.vout = static_cast<uint32_t>(std::stoul(parts[1]));
    input.value = static_cast<uint64_t>(std::stoull(parts[2]));
    input.prev_script = from_hex(parts[3]);
    inputs.push_back(input);
  }
  if (inputs.empty()) throw std::runtime_error("no inputs");
  return inputs;
}

std::vector<TxOut> parse_outputs(const std::string& encoded) {
  std::vector<TxOut> outputs;
  if (encoded.empty()) throw std::runtime_error("outputs are required");
  for (const auto& row : split(encoded, '|')) {
    if (row.empty()) continue;
    const auto parts = split(row, ':');
    if (parts.size() != 2) throw std::runtime_error("invalid output row");
    outputs.push_back({static_cast<uint64_t>(std::stoull(parts[0])), from_hex(parts[1])});
  }
  if (outputs.empty()) throw std::runtime_error("no outputs");
  return outputs;
}

}  // namespace

SignedTransactionResult sign_utxo_transaction(const std::map<std::string, std::string>& params) {
  const auto mnemonic = get_param(params, "phrase");
  const auto derivation_path = get_param(params, "derivationPath");
  if (mnemonic.empty()) throw std::runtime_error("wallet phrase is required");
  if (derivation_path.empty()) throw std::runtime_error("derivationPath is required");

  auto inputs = parse_inputs(get_param(params, "inputs"));
  const auto outputs = parse_outputs(get_param(params, "outputs"));
  const auto tx_version = parse_tx_version(params);
  const bool use_bip143 = get_param(params, "sighashStyle") == "bip143-forkid";
  const bool use_taproot = get_param(params, "sighashStyle") == "taproot" || get_param(params, "addressType") == "p2tr";
  const auto key_material = derive_wallet_key_material(mnemonic, derivation_path);

  std::unique_ptr<secp256k1_context, SecpContextDeleter> ctx(secp256k1_context_create(SECP256K1_CONTEXT_NONE));
  if (!ctx) throw std::runtime_error("secp256k1 context creation failed");

  bool has_witness = false;
  for (size_t i = 0; i < inputs.size(); ++i) {
    const auto& script_code = inputs[i].prev_script;
    if (use_taproot) {
      if (!is_p2tr_script(script_code)) throw std::runtime_error("taproot transaction requires p2tr inputs");
      inputs[i].witness = {sign_taproot_key_path(
        ctx.get(),
        taproot_sighash(inputs, outputs, i, tx_version),
        key_material.private_key
      )};
      has_witness = true;
    } else if (is_p2wpkh_script(script_code)) {
      inputs[i].witness = sign_input_segwit_v0(
        ctx.get(),
        inputs,
        outputs,
        i,
        p2pkh_script(Bytes(script_code.begin() + 2, script_code.end())),
        key_material.private_key,
        key_material.public_key,
        use_bip143 ? SIGHASH_ALL_FORKID : SIGHASH_ALL,
        tx_version
      );
      has_witness = true;
    } else if (use_bip143) {
      inputs[i].script_sig = sign_input_bip143_forkid(
        ctx.get(),
        inputs,
        outputs,
        i,
        script_code,
        key_material.private_key,
        key_material.public_key,
        tx_version
      );
    } else {
      inputs[i].script_sig = sign_input_legacy(
        ctx.get(),
        inputs,
        outputs,
        i,
        script_code,
        key_material.private_key,
        key_material.public_key,
        tx_version
      );
    }
  }

  const auto signed_bytes = serialize_tx(inputs, outputs, has_witness, tx_version);
  auto txid_bytes = hash256(serialize_tx(inputs, outputs, false, tx_version));
  std::reverse(txid_bytes.begin(), txid_bytes.end());
  return {to_hex(signed_bytes), to_hex(txid_bytes)};
}

}  // namespace altbase
