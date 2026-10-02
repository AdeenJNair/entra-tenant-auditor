#pragma once
#include <string>

struct HttpResponse {
    long status = 0;   // HTTP status code, e.g. 200, 401
    std::string body;  // whole response body, buffered
};

// Both throw std::runtime_error if the request could not be completed at all
// (DNS, TLS, timeout...). A 4xx/5xx reply is NOT an exception: the caller
// inspects `status`.
HttpResponse http_post_form(const std::string& url, const std::string& form_body);
HttpResponse http_get(const std::string& url, const std::string& bearer_token);

// Percent-encodes a value for use inside a form body ("a b&c" -> "a%20b%26c").
std::string url_encode(const std::string& value);
