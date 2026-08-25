#include "privacy_light_wallet.hpp"

#include "epic_module_api.hpp"
#include "wallet_secret.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace altbase {
namespace {

std::string get_param(const std::map<std::string, std::string>& params, const std::string& key) {
  const auto it = params.find(key);
  return it == params.end() ? "" : it->second;
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

PrivacyLightWalletResult not_ready(std::string code, std::string error) {
  PrivacyLightWalletResult result;
  result.code = std::move(code);
  result.error = std::move(error);
  result.balance = "0";
  result.spendable = "0";
  result.transactions = "[]";
  return result;
}

bool is_decimal_number(const std::string& value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return std::isdigit(ch) != 0;
  });
}

std::string json_escape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char ch : value) {
    switch (ch) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (ch < 0x20) {
          out += "\\u00";
          out.push_back(hex[(ch >> 4U) & 0x0fU]);
          out.push_back(hex[ch & 0x0fU]);
        } else {
          out.push_back(static_cast<char>(ch));
        }
    }
  }
  return out;
}

void append_utf8(std::string& out, unsigned value) {
  if (value <= 0x7fU) {
    out.push_back(static_cast<char>(value));
  } else if (value <= 0x7ffU) {
    out.push_back(static_cast<char>(0xc0U | (value >> 6U)));
    out.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
  } else {
    out.push_back(static_cast<char>(0xe0U | (value >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
  }
}

class JsonObjectReader {
 public:
  explicit JsonObjectReader(std::string_view text) : text_(text) {}

  std::string string(const std::string& key) const {
    const auto range = value_range(key);
    if (!range || range->first >= range->second || text_[range->first] != '"') return "";
    return decode_string(range->first, range->second);
  }

  std::string number(const std::string& key) const {
    const auto range = value_range(key);
    if (!range) return "";
    if (text_[range->first] == '"') return decode_string(range->first, range->second);
    return trim(text_.substr(range->first, range->second - range->first));
  }

  bool boolean(const std::string& key) const {
    const auto range = value_range(key);
    return range && trim(text_.substr(range->first, range->second - range->first)) == "true";
  }

  std::string array(const std::string& key) const {
    const auto range = value_range(key);
    if (!range || text_[range->first] != '[') return "[]";
    return std::string(text_.substr(range->first, range->second - range->first));
  }

 private:
  using Range = std::pair<size_t, size_t>;

  static std::string trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) value.remove_suffix(1);
    return std::string(value);
  }

  void whitespace(size_t& pos) const {
    while (pos < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos])) != 0) ++pos;
  }

  size_t string_end(size_t start) const {
    bool escaped = false;
    for (size_t pos = start + 1; pos < text_.size(); ++pos) {
      const char ch = text_[pos];
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        return pos + 1;
      }
    }
    return text_.size();
  }

  size_t value_end(size_t start) const {
    if (start >= text_.size()) return start;
    if (text_[start] == '"') return string_end(start);
    if (text_[start] == '[' || text_[start] == '{') {
      const char open = text_[start];
      const char close = open == '[' ? ']' : '}';
      int depth = 0;
      bool in_string = false;
      bool escaped = false;
      for (size_t pos = start; pos < text_.size(); ++pos) {
        const char ch = text_[pos];
        if (in_string) {
          if (escaped) escaped = false;
          else if (ch == '\\') escaped = true;
          else if (ch == '"') in_string = false;
          continue;
        }
        if (ch == '"') in_string = true;
        else if (ch == open) ++depth;
        else if (ch == close && --depth == 0) return pos + 1;
      }
      return text_.size();
    }
    size_t pos = start;
    while (pos < text_.size() && text_[pos] != ',' && text_[pos] != '}') ++pos;
    while (pos > start && std::isspace(static_cast<unsigned char>(text_[pos - 1])) != 0) --pos;
    return pos;
  }

  std::optional<Range> value_range(const std::string& wanted) const {
    size_t pos = 0;
    whitespace(pos);
    if (pos >= text_.size() || text_[pos++] != '{') return std::nullopt;
    while (pos < text_.size()) {
      whitespace(pos);
      if (pos < text_.size() && text_[pos] == '}') return std::nullopt;
      if (pos >= text_.size() || text_[pos] != '"') return std::nullopt;
      const size_t key_start = pos;
      const size_t key_end = string_end(pos);
      const auto key = decode_string(key_start, key_end);
      pos = key_end;
      whitespace(pos);
      if (pos >= text_.size() || text_[pos++] != ':') return std::nullopt;
      whitespace(pos);
      const size_t start = pos;
      const size_t end = value_end(start);
      if (key == wanted) return Range{start, end};
      pos = end;
      whitespace(pos);
      if (pos < text_.size() && text_[pos] == ',') ++pos;
    }
    return std::nullopt;
  }

  std::string decode_string(size_t start, size_t end) const {
    if (end <= start + 1 || text_[start] != '"') return "";
    std::string out;
    for (size_t pos = start + 1; pos + 1 < end; ++pos) {
      char ch = text_[pos];
      if (ch != '\\') {
        out.push_back(ch);
        continue;
      }
      if (++pos + 1 >= end) break;
      ch = text_[pos];
      switch (ch) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (pos + 4 >= end) break;
          unsigned value = 0;
          bool valid = true;
          for (size_t digit = 0; digit < 4; ++digit) {
            const char hex = text_[++pos];
            value <<= 4U;
            if (hex >= '0' && hex <= '9') value |= static_cast<unsigned>(hex - '0');
            else if (hex >= 'a' && hex <= 'f') value |= static_cast<unsigned>(hex - 'a' + 10);
            else if (hex >= 'A' && hex <= 'F') value |= static_cast<unsigned>(hex - 'A' + 10);
            else valid = false;
          }
          if (valid) append_utf8(out, value);
          break;
        }
        default: out.push_back(ch); break;
      }
    }
    return out;
  }

  std::string_view text_;
};

std::string epic_work_dir(const std::map<std::string, std::string>& params, const std::string& scope) {
  const auto configured = get_param(params, "userDataDir");
  std::filesystem::path base = configured.empty() ? std::filesystem::current_path() : std::filesystem::path(configured);
  const auto path = base / "epic-light" / ("altbase-epic-v1-" + scope);
  std::filesystem::create_directories(path);
  return path.string();
}

std::string epic_node_url(const std::map<std::string, std::string>& params) {
  const auto configured = get_param(params, "epicNodeUrl");
  return configured.empty() ? "https://api.altbase.io" : configured;
}

std::string call_epic_module(const std::string& request, const std::string& action) {
  const bool sending = action == "send" || action == "estimatemax";
  char* raw = sending
    ? altbase_epic_sender_request(request.c_str())
    : altbase_epic_state_request(request.c_str());
  if (!raw) throw std::runtime_error("Epic wallet module returned no response");
  std::string response(raw);
  if (sending) altbase_epic_sender_free(raw);
  else altbase_epic_state_free(raw);
  return response;
}

std::string build_request(
  const std::map<std::string, std::string>& params,
  const std::string& action,
  const std::string& mnemonic,
  const PrivacyWalletSecretResult& secret
) {
  std::ostringstream request;
  request << "{\"action\":\"" << json_escape(action) << "\","
          << "\"phrase\":\"" << json_escape(mnemonic) << "\","
          << "\"password\":\"" << json_escape(secret.engine_password) << "\","
          << "\"dataDir\":\"" << json_escape(epic_work_dir(params, secret.scope)) << "\","
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
  request << '}';
  return request.str();
}

PrivacyLightWalletResult result_from_response(const std::string& response) {
  const JsonObjectReader json(response);
  PrivacyLightWalletResult result;
  result.ok = json.boolean("ok");
  result.code = json.string("code");
  result.error = json.string("error");
  result.address = json.string("address");
  result.balance = json.string("balance");
  result.spendable = json.string("spendable");
  result.txid = json.string("txid");
  result.amount = json.string("amount");
  result.fee = json.string("fee");
  result.transactions = json.array("transactions");
  result.last_scanned_height = json.number("lastScannedHeight");
  if (result.last_scanned_height.empty()) result.last_scanned_height = json.number("last_scanned_height");
  if (result.balance.empty()) result.balance = "0";
  if (result.spendable.empty()) result.spendable = result.balance;
  if (result.transactions.empty()) result.transactions = "[]";
  return result;
}

}  // namespace

PrivacyLightWalletResult privacy_light_wallet(const std::map<std::string, std::string>& params) {
  if (lower(get_param(params, "coin")) != "epic") {
    return not_ready("bad-coin", "Unsupported Epic wallet coin");
  }

  auto action = lower(get_param(params, "action"));
  if (action == "warm") action = "ensure";
  if (action != "ensure" && action != "snapshot" && action != "send" && action != "estimatemax") {
    return not_ready("bad-action", "Unsupported Epic wallet action");
  }

  const auto mnemonic = get_param(params, "phrase");
  if (mnemonic.empty()) {
    if (action != "snapshot") {
      return not_ready("epic-wallet-unlock-required", "Epic wallet must be unlocked");
    }
    auto result = not_ready("epic-native-snapshot-needs-unlock", "");
    result.ok = true;
    return result;
  }

  try {
    const auto secret = privacy_wallet_secret({{"coin", "epic"}, {"phrase", mnemonic}});
    const auto request = build_request(params, action, mnemonic, secret);
    auto result = result_from_response(call_epic_module(request, action));

    if (result.address.empty() && action != "ensure") {
      const auto ensure_request = build_request(params, "ensure", mnemonic, secret);
      result.address = result_from_response(call_epic_module(ensure_request, "ensure")).address;
    }
    return result;
  } catch (const std::exception& error) {
    return not_ready("epic-native-wallet-error", error.what());
  }
}

}  // namespace altbase
