#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

#include "audit.hpp"
#include "graph.hpp"
#include "guard.hpp"
#include "report.hpp"
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

// Runs one audit module. If it fails (missing permission, missing licence...)
// the other modules still run, and the failure is recorded in `skipped` so the
// report says plainly what was NOT audited.
static void run_module(const std::string& name,
                       const std::function<std::vector<Finding>()>& module,
                       std::vector<Finding>& findings,
                       std::vector<std::string>& skipped) {
    try {
        const auto part = module();
        findings.insert(findings.end(), part.begin(), part.end());
    } catch (const std::exception& e) {
        skipped.push_back(name + ": " + e.what());
    }
}

int main() {
    try {
        const std::string tenant_id = require_env("ENTRA_TENANT_ID");
        const std::string client_id = require_env("ENTRA_CLIENT_ID");
        const std::string secret    = require_env("ENTRA_CLIENT_SECRET");
        const std::string lab_id    = require_env("ENTRA_LAB_TENANT_ID");

        std::cout << "Auditing tenant " << tenant_id << "\n";
        const AccessToken token = fetch_token(tenant_id, client_id, secret);
        enforce_lab_guardrail(token.value, lab_id);  // throws -> nothing below runs

        const auto users = graph_get_all(
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,displayName,userPrincipalName,userType,accountEnabled,externalUserState"
            "&$top=999",
            token.value);
        std::cout << "Users in tenant: " << users.size() << "\n\n";

        std::vector<Finding> findings;
        std::vector<std::string> skipped;
        run_module("Guests", [&] { return audit_guests(users); }, findings, skipped);
        run_module("MFA registration", [&] { return audit_mfa(users, token.value); }, findings, skipped);
        run_module("Privileged roles", [&] { return audit_roles(token.value); }, findings, skipped);
        run_module("Conditional Access", [&] { return audit_conditional_access(users, token.value); }, findings, skipped);
        run_module("Intune devices", [&] { return audit_devices(token.value); }, findings, skipped);

        escalate_privileged_without_mfa(findings);

        // Worst first. The enum is declared Low < Medium < High, so descending
        // order puts High at the top. stable_sort keeps the original order among
        // findings of equal severity.
        std::stable_sort(findings.begin(), findings.end(),
                         [](const Finding& a, const Finding& b) { return a.severity > b.severity; });

        print_findings(findings);
        std::cout << "\n" << findings.size() << " finding(s)\n";
        for (const auto& s : skipped) std::cout << "NOT AUDITED - " << s << "\n";

        std::filesystem::create_directories("reports");
        write_csv("reports/audit.csv", findings);
        write_html("reports/audit.html", findings, tenant_id, skipped);
        std::cout << "Wrote reports/audit.csv and reports/audit.html\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
