#include "address_validation.hpp"
#include "protocol.hpp"
#include "tx_planning.hpp"
#include "wallet_derivation.hpp"
#include "wallet_secret.hpp"

#include <cstdlib>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

void test_protocol() {
  std::string error;
  const auto request = altbase::parse_request(
    R"({"params":{"apostrophe":"\u0027","emoji":"\uD83D\uDE00","height":42},"method":"health","id":"7"})",
    error
  );
  require(request.has_value(), "valid request was rejected: " + error);
  require(request->id == "7" && request->method == "health", "request envelope was parsed incorrectly");
  require(request->params.at("apostrophe") == "'", "unicode apostrophe was parsed incorrectly");
  require(request->params.at("emoji") == "\xF0\x9F\x98\x80", "surrogate pair was parsed incorrectly");
  require(request->params.at("height") == "42", "numeric parameter was parsed incorrectly");

  require(!altbase::parse_request(R"({"id":"1","method":"health","params":{}} trailing)", error),
          "trailing request data was accepted");
  require(!altbase::parse_request(R"({"id":"1","id":"2","method":"health","params":{}})", error),
          "duplicate request id was accepted");
  require(!altbase::parse_request(R"({"id":"1","method":"health","params":{"bad":"\uD800"}})", error),
          "lone unicode surrogate was accepted");
  require(!altbase::parse_request(R"({"id":"1","method":"health","params":[]})", error),
          "non-object params were accepted");
}

void test_bitcoin_bip84() {
  const std::map<std::string, std::string> params{
    {"phrase", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
    {"derivationPath", "m/84'/0'/0'/0/0"},
    {"addressType", "p2wpkh"},
    {"p2pkhPrefix", "0"},
    {"p2shPrefix", "5"},
    {"wifPrefix", "128"},
    {"bech32Hrp", "bc"},
  };
  const auto derived = altbase::derive_wallet_material(params);
  require(derived.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "Bitcoin BIP84 vector mismatch");

  const auto validated = altbase::validate_address({
    {"address", derived.address},
    {"bech32Hrp", "bc"},
    {"p2pkhPrefix", "0"},
    {"p2shPrefix", "5"},
  });
  require(validated.is_valid && validated.script_kind == "p2wpkh", "derived Bitcoin address failed validation");
  require(validated.script_pub_key == "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2", "Bitcoin scriptPubKey mismatch");
}

void test_wallet_secret() {
  const std::string phrase =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const std::string password = "native-core-test-password";
  const auto secret = altbase::create_wallet_secret({{"phrase", phrase}, {"password", password}});

  require(altbase::verify_wallet_password({
    {"password", password}, {"verifySalt", secret.verify_salt}, {"verifyHash", secret.verify_hash},
  }), "wallet password verification failed");
  require(!altbase::verify_wallet_password({
    {"password", "wrong-password"}, {"verifySalt", secret.verify_salt}, {"verifyHash", secret.verify_hash},
  }), "wrong wallet password was accepted");
  require(altbase::decrypt_wallet_secret({
    {"password", password}, {"cipherText", secret.cipher_text}, {"iv", secret.iv}, {"salt", secret.salt},
  }) == phrase, "wallet secret roundtrip failed");

  auto tampered = secret.cipher_text;
  tampered.front() = tampered.front() == 'A' ? 'B' : 'A';
  bool rejected = false;
  try {
    (void)altbase::decrypt_wallet_secret({
      {"password", password}, {"cipherText", tampered}, {"iv", secret.iv}, {"salt", secret.salt},
    });
  } catch (...) {
    rejected = true;
  }
  require(rejected, "tampered wallet ciphertext was accepted");
}

void test_transaction_planning() {
  const std::string txid(64, '1');
  const auto plan = altbase::plan_utxo_transaction({
    {"mode", "amount"},
    {"utxos", txid + ":0:100000:0014abcd"},
    {"amountSats", "50000"},
    {"manualFeeSats", "1000"},
    {"toScript", "0014feed"},
    {"changeScript", "0014beef"},
  });
  require(plan.amount_satoshis == 50000 && plan.fee_satoshis == 1000, "UTXO amount or fee mismatch");
  require(plan.input_count == 1, "UTXO input selection mismatch");
  require(plan.outputs == "50000:0014feed|49000:0014beef", "UTXO change output mismatch");

  bool rejected = false;
  try {
    (void)altbase::plan_utxo_transaction({
      {"mode", "amount"},
      {"utxos", txid + ":0:1000:0014abcd"},
      {"amountSats", "1000"},
      {"manualFeeSats", "1"},
      {"toScript", "0014feed"},
      {"changeScript", "0014beef"},
    });
  } catch (...) {
    rejected = true;
  }
  require(rejected, "insufficient UTXO balance was accepted");
}

}  // namespace

int main() {
  try {
    test_protocol();
    test_bitcoin_bip84();
    test_wallet_secret();
    test_transaction_planning();
    std::cout << "altbase_core_tests: ok\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << "altbase_core_tests: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
