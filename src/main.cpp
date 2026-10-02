#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "audit.hpp"
#include "graph.hpp"
#include "token.hpp"

// std::getenv returns char* (NULL if unset). Wrap it so the rest of the code
// only ever sees a std::string and a clear error.
static std::string require_env(const char* name) {
    const char* value = std::getenv(name);
    if (!value || !*value) throw std::runtime_error(std::string("Missing environment variable: ") + name);
    return value;
}

static void print_findings(const std::vector<Finding>& findings) {
    for (const auto& f : findings) {
        std::cout << "[" << to_string(f.severity) << "] " << f.category << ": " << f.subject
                  << "\n    " << f.detail << "\n    Why: " << f.why << "\n";
    }
}

int main() {
    try {
        const std::string tenant_id = require_env("ENTRA_TENANT_ID");
        const std::string client_id = require_env("ENTRA_CLIENT_ID");
        const std::string secret    = require_env("ENTRA_CLIENT_SECRET");

        std::cout << "Auditing tenant " << tenant_id << "\n";
        const AccessToken token = fetch_token(tenant_id, client_id, secret);

        const auto users = graph_get_all(
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState"
            "&$top=999",
            token.value);
        std::cout << "Users in tenant: " << users.size() << "\n\n";

        std::vector<Finding> findings = audit_guests(users);
        const auto mfa_findings = audit_mfa(users, token.value);
        findings.insert(findings.end(), mfa_findings.begin(), mfa_findings.end());

        print_findings(findings);
        std::cout << "\n" << findings.size() << " finding(s)\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
