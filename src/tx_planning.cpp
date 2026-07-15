#include "tx_planning.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace altbase {
namespace {

constexpr uint64_t MIN_RELAY_FEE = 1000;
constexpr uint64_t DUST_THRESHOLD = 546;

struct UtxoRow {
  std::string txid;
  uint32_t vout = 0;
  uint64_t satoshis = 0;
  std::string script;
};

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

uint64_t to_u64(const std::map<std::string, std::string>& params, const std::string& key, uint64_t fallback = 0) {
  const auto value = get_param(params, key);
  if (value.empty()) return fallback;
  return static_cast<uint64_t>(std::stoull(value));
}

double to_double(const std::map<std::string, std::string>& params, const std::string& key, double fallback = 0) {
  const auto value = get_param(params, key);
  if (value.empty()) return fallback;
  std::istringstream input(value);
  input.imbue(std::locale::classic());
  double parsed = fallback;
  input >> parsed;
  return input.fail() ? fallback : parsed;
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

std::vector<UtxoRow> parse_utxos(const std::string& encoded) {
  std::vector<UtxoRow> utxos;
  if (encoded.empty()) return utxos;
  for (const auto& row : split(encoded, '|')) {
    if (row.empty()) continue;
    const auto parts = split(row, ':');
    if (parts.size() != 4) throw std::runtime_error("invalid utxo row");
    utxos.push_back({
      parts[0],
      static_cast<uint32_t>(std::stoul(parts[1])),
      static_cast<uint64_t>(std::stoull(parts[2])),
      parts[3],
    });
  }
  return utxos;
}

uint64_t estimate_bytes(uint64_t input_count, uint64_t output_count) {
  return 10 + 148 * input_count + 34 * output_count;
}

uint64_t calc_fee(double fee_rate_per_kb, uint64_t sats_per_coin, uint64_t input_count, uint64_t output_count) {
  const auto bytes = static_cast<double>(estimate_bytes(input_count, output_count));
  const auto sats = static_cast<uint64_t>(std::ceil((fee_rate_per_kb * bytes * static_cast<double>(sats_per_coin) * 1.2) / 1000.0));
  return std::max<uint64_t>(MIN_RELAY_FEE, sats);
}

std::vector<UtxoRow> select_utxos(std::vector<UtxoRow> utxos, uint64_t target) {
  std::sort(utxos.begin(), utxos.end(), [](const auto& a, const auto& b) {
    return a.satoshis > b.satoshis;
  });
  std::vector<UtxoRow> selected;
  uint64_t sum = 0;
  for (const auto& utxo : utxos) {
    selected.push_back(utxo);
    sum += utxo.satoshis;
    if (sum >= target) break;
  }
  return selected;
}

uint64_t sum_utxos(const std::vector<UtxoRow>& utxos) {
  uint64_t sum = 0;
  for (const auto& utxo : utxos) sum += utxo.satoshis;
  return sum;
}

std::string encode_inputs(const std::vector<UtxoRow>& inputs) {
  std::string encoded;
  for (const auto& input : inputs) {
    if (!encoded.empty()) encoded += "|";
    encoded += input.txid + ":" +
               std::to_string(input.vout) + ":" +
               std::to_string(input.satoshis) + ":" +
               input.script;
  }
  return encoded;
}

std::string encode_outputs(uint64_t amount, const std::string& to_script, uint64_t change, const std::string& change_script) {
  std::string outputs = std::to_string(amount) + ":" + to_script;
  if (change > DUST_THRESHOLD) outputs += "|" + std::to_string(change) + ":" + change_script;
  return outputs;
}

}  // namespace

FeeEstimateResult estimate_transaction_fee(const std::map<std::string, std::string>& params) {
  return {
    calc_fee(
      to_double(params, "feeRatePerKb", 0.00001),
      to_u64(params, "satsPerCoin", 100000000),
      to_u64(params, "nIn", 1),
      to_u64(params, "nOut", 2)
    )
  };
}

TransactionPlanResult plan_utxo_transaction(const std::map<std::string, std::string>& params) {
  const auto mode = get_param(params, "mode");
  const auto utxos = parse_utxos(get_param(params, "utxos"));
  if (utxos.empty()) throw std::runtime_error("No spendable UTXOs (balance is 0 or unconfirmed)");

  const auto sats_per_coin = to_u64(params, "satsPerCoin", 100000000);
  const auto fee_rate = to_double(params, "feeRatePerKb", 0.00001);
  const auto manual_fee = to_u64(params, "manualFeeSats", 0);
  if (manual_fee == 0 && get_param(params, "manualFeeSats") == "0") throw std::runtime_error("Fee must be greater than 0");

  if (mode == "max") {
    const auto sum = sum_utxos(utxos);
    const auto fee = manual_fee > 0 ? manual_fee : calc_fee(fee_rate, sats_per_coin, utxos.size(), 1);
    if (fee == 0) throw std::runtime_error("Fee must be greater than 0");
    if (sum <= fee) throw std::runtime_error("Insufficient balance for the amount and network fee");
    const auto to_script = get_param(params, "toScript");
    return {
      sum - fee,
      fee,
      static_cast<uint64_t>(utxos.size()),
      encode_inputs(utxos),
      to_script.empty() ? "" : encode_outputs(sum - fee, to_script, 0, ""),
    };
  }

  const auto amount = to_u64(params, "amountSats");
  if (amount == 0) throw std::runtime_error("Amount must be greater than 0");
  const auto to_script = get_param(params, "toScript");
  const auto change_script = get_param(params, "changeScript");
  if (to_script.empty() || change_script.empty()) throw std::runtime_error("output scripts are required");

  uint64_t fee = manual_fee > 0 ? manual_fee : calc_fee(fee_rate, sats_per_coin, 1, 2);
  for (int pass = 0; pass < 5; ++pass) {
    const auto selected = select_utxos(utxos, amount + fee);
    const auto sum = sum_utxos(selected);
    const auto change = sum > amount + fee ? sum - amount - fee : 0;
    const auto output_count = change > DUST_THRESHOLD ? 2 : 1;
    const auto next_fee = manual_fee > 0 ? manual_fee : calc_fee(fee_rate, sats_per_coin, std::max<size_t>(1, selected.size()), output_count);
    if (next_fee == fee) break;
    fee = next_fee;
  }

  const auto selected = select_utxos(utxos, amount + fee);
  const auto sum = sum_utxos(selected);
  if (sum < amount + fee) throw std::runtime_error("Insufficient funds");
  const auto change = sum - amount - fee;

  return {
    amount,
    fee,
    static_cast<uint64_t>(selected.size()),
    encode_inputs(selected),
    encode_outputs(amount, to_script, change, change_script),
  };
}

}  // namespace altbase
