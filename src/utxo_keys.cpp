#include "utxo_keys.hpp"

#if defined(ALTBASE_UTXO_ADDRESS_SERVICE)
#include "address_validation.hpp"
#elif defined(ALTBASE_UTXO_DERIVATION_SERVICE)
#include "wallet_derivation.hpp"
#else
#error A UTXO key service must be selected
#endif

#include <stdexcept>

namespace altbase {

std::map<std::string, std::string> handle_utxo_keys(const Request& request) {
#if defined(ALTBASE_UTXO_ADDRESS_SERVICE)
  if (request.method == "validateAddress") {
    const auto validation = validate_address(request.params);
    return {
      {"isValid", validation.is_valid ? "true" : "false"}, {"format", validation.format},
      {"scriptKind", validation.script_kind}, {"scriptPubKey", validation.script_pub_key}, {"error", validation.error},
    };
  }
  if (request.method == "addressToScript") {
    const auto validation = validate_address(request.params);
    if (!validation.is_valid) throw std::runtime_error("invalid address: " + validation.error);
    return {{"scriptPubKey", validation.script_pub_key}, {"format", validation.format}, {"scriptKind", validation.script_kind}};
  }
  if (request.method == "addressVariantsFromLegacy") {
    const auto variants = address_variants_from_legacy(request.params);
    std::string encoded;
    for (const auto& variant : variants) {
      if (!encoded.empty()) encoded += '|';
      encoded += variant.id + ',' + variant.label + ',' + variant.address + ',' + variant.script_kind + ',' +
        (variant.alias_of_legacy ? "true" : "false");
    }
    return {{"variants", encoded}};
  }
  throw std::runtime_error("unknown UTXO address method: " + request.method);
#else
  if (request.method == "deriveAddress" || request.method == "deriveWif") {
    const auto material = derive_wallet_material(request.params);
    if (request.method == "deriveAddress") return {{"address", material.address}, {"publicKey", material.public_key_hex}};
    return {{"wif", material.private_key_wif}, {"address", material.address}, {"publicKey", material.public_key_hex}};
  }
  throw std::runtime_error("unknown UTXO derivation method: " + request.method);
#endif
}

}  // namespace altbase
