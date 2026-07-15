#include "utxo_tx.hpp"

#if defined(ALTBASE_UTXO_SIGNER_SERVICE)
#include "tx_signing.hpp"
#elif defined(ALTBASE_UTXO_PLANNER_SERVICE)
#include "tx_planning.hpp"
#else
#error A UTXO transaction service must be selected
#endif

#include <stdexcept>

namespace altbase {

std::map<std::string, std::string> handle_utxo_tx(const Request& request) {
#if defined(ALTBASE_UTXO_SIGNER_SERVICE)
  if (request.method == "signTransaction") {
    const auto signed_tx = sign_utxo_transaction(request.params);
    return {{"txHex", signed_tx.tx_hex}, {"txid", signed_tx.txid}};
  }
  throw std::runtime_error("unknown UTXO signer method: " + request.method);
#else
  if (request.method == "estimateFee") {
    const auto fee = estimate_transaction_fee(request.params);
    return {{"feeSatoshis", std::to_string(fee.fee_satoshis)}};
  }
  if (request.method == "planTransaction") {
    const auto plan = plan_utxo_transaction(request.params);
    return {
      {"amountSatoshis", std::to_string(plan.amount_satoshis)}, {"feeSatoshis", std::to_string(plan.fee_satoshis)},
      {"inputCount", std::to_string(plan.input_count)}, {"selectedInputs", plan.selected_inputs}, {"outputs", plan.outputs},
    };
  }
  throw std::runtime_error("unknown UTXO planner method: " + request.method);
#endif
}

}  // namespace altbase
