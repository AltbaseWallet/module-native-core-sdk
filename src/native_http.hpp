#pragma once

#include <map>
#include <string>

namespace altbase {

struct HttpResponse {
  int status = 0;
  std::string body;
  std::map<std::string, std::string> headers;
};

HttpResponse http_get(const std::string& url, unsigned long timeout_ms = 30000);
HttpResponse http_post_json(const std::string& url, const std::string& body, unsigned long timeout_ms = 30000);
HttpResponse http_post_binary(const std::string& url, const std::string& body, unsigned long timeout_ms = 30000);

}  // namespace altbase
