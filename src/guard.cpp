#include "guard.hpp"

#include <nlohmann/json.hpp>

#include <iostream>
#include <stdexcept>

namespace {

// JWTs are base64url: '-' and '_' replace '+' and '/', and padding is dropped.
// Each input char contributes 6 bits; every time we hold 8 or more, one output
// byte is complete.
std::string base64url_decode(const std::string& in) {
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    unsigned val = 0;
    int bits = -8;
    for (char c : in) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        else if (c == '=') break;
        const size_t idx = alphabet.find(c);
        if (idx == std::string::npos) throw std::runtime_error("Token is not valid base64url");
        val = ((val << 6) + static_cast<unsigned>(idx)) & 0xFFFFFF;  // mask: avoid overflow
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

}  // namespace

void enforce_lab_guardrail(const std::string& access_token,
                           const std::string& expected_tenant_id) {
    // A JWT is header.payload.signature. We only need the middle part.
    const size_t first = access_token.find('.');
    const size_t second = first == std::string::npos ? first : access_token.find('.', first + 1);
    if (second == std::string::npos) throw std::runtime_error("Access token is not a JWT");

    // We do NOT verify the signature: the token came straight from Microsoft
    // over TLS, and we only read it to decide whether to REFUSE to run.
    // (A server receiving tokens from others must always verify them.)
    const auto claims = nlohmann::json::parse(
        base64url_decode(access_token.substr(first + 1, second - first - 1)));

    const std::string tid = claims.value("tid", "");
    if (tid != expected_tenant_id)
        throw std::runtime_error("Refusing to run: token is for tenant '" + tid +
                                 "', not the lab tenant in ENTRA_LAB_TENANT_ID");

    std::string granted;  // collect first, print only after every check passed
    if (claims.contains("roles") && claims["roles"].is_array()) {
        for (const auto& r : claims["roles"]) {
            const std::string role = r.get<std::string>();
            if (role.find("Write") != std::string::npos)
                throw std::runtime_error("Refusing to run: token holds write permission '" +
                                         role + "'. This tool must be read-only.");
            granted += (granted.empty() ? "" : ", ") + role;
        }
    }
    std::cout << "Guardrail OK: tenant matches the lab tenant.\nToken permissions: "
              << (granted.empty() ? "(none)" : granted) << "\n";
}
