#pragma once

#include "protocol.hpp"

#include <map>
#include <string>

namespace altbase {
std::map<std::string, std::string> handle_utxo_tx(const Request& request);
}
