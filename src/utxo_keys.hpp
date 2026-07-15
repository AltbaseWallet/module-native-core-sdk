#pragma once

#include "protocol.hpp"

#include <map>
#include <string>

namespace altbase {
std::map<std::string, std::string> handle_utxo_keys(const Request& request);
}
