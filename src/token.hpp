#pragma once
#include <string>

struct AccessToken {
    std::string value;   // the bearer token. TREAT AS A SECRET, never log it.
    int expires_in = 0;  // seconds until it stops working (typically ~3600)
};

// OAuth2 client-credentials grant against the Microsoft identity platform.
// Throws std::runtime_error with Microsoft's error text on failure.
AccessToken fetch_token(const std::string& tenant_id,
                        const std::string& client_id,
                        const std::string& client_secret);
