#pragma once

#include <map>
#include <string>
#include <vector>

namespace altbase {

struct AddressValidationResult {
  bool is_valid = false;
  std::string format;
  std::string script_kind;
  std::string script_pub_key;
  std::string error;
};

struct AddressVariantResult {
  std::string id;
  std::string label;
  std::string address;
  std::string script_kind;
  bool alias_of_legacy = false;
};

AddressValidationResult validate_address(const std::map<std::string, std::string>& params);
std::vector<AddressVariantResult> address_variants_from_legacy(const std::map<std::string, std::string>& params);

}  // namespace altbase
