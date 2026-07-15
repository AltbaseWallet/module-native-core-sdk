#pragma once

#include <map>
#include <optional>
#include <string>

namespace altbase {

struct Request {
  std::string id;
  std::string method;
  std::map<std::string, std::string> params;
};

std::optional<Request> parse_request(const std::string& line, std::string& error);
std::string ok_response(const std::string& id, const std::map<std::string, std::string>& fields);
std::string error_response(const std::string& id, const std::string& code, const std::string& message);
std::string json_escape(const std::string& value);

}  // namespace altbase
