#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "token.hpp"

// std::getenv returns char* (NULL if unset). Wrap it so the rest of the code
// only ever sees a std::string and a clear error.
static std::string require_env(const char* name) {
    const char* value = std::getenv(name);
    if (!value || !*value) throw std::runtime_error(std::string("Missing environment variable: ") + name);
    return value;
}

int main() {
    try {
        const std::string tenant_id = require_env("ENTRA_TENANT_ID");
        const std::string client_id = require_env("ENTRA_CLIENT_ID");
        const std::string secret    = require_env("ENTRA_CLIENT_SECRET");

        std::cout << "Requesting token for tenant " << tenant_id << " ...\n";
        const AccessToken token = fetch_token(tenant_id, client_id, secret);

        // Never print the token itself.
        std::cout << "OK: got a token (" << token.value.size()
                  << " chars), valid for " << token.expires_in << " seconds\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
