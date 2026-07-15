#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace altbase {

struct FeeEstimateResult {
  uint64_t fee_satoshis = 0;
};

struct TransactionPlanResult {
  uint64_t amount_satoshis = 0;
  uint64_t fee_satoshis = 0;
  uint64_t input_count = 0;
  std::string selected_inputs;
  std::string outputs;
};

FeeEstimateResult estimate_transaction_fee(const std::map<std::string, std::string>& params);
TransactionPlanResult plan_utxo_transaction(const std::map<std::string, std::string>& params);

}  // namespace altbase
