#include "audit.hpp"

#include "graph.hpp"

std::vector<Finding> audit_guests(const std::vector<nlohmann::json>& users) {
    std::vector<Finding> findings;
    for (const auto& u : users) {
        if (u.value("userType", "") != "Guest") continue;

        const std::string upn = u.value("userPrincipalName", "?");
        const std::string state = u.value("externalUserState", "");
        findings.push_back({
            Severity::Low, "Guest", upn,
            state.empty() ? "External guest account" : "External guest account (" + state + ")",
            "Guests are outside your control: review who they are and what they can reach."});
    }
    return findings;
}

std::vector<Finding> audit_mfa(const std::vector<nlohmann::json>& users,
                               const std::string& bearer_token) {
    std::vector<Finding> findings;
    for (const auto& u : users) {
        if (!u.value("accountEnabled", true)) continue;  // disabled accounts can't sign in

        const std::string id  = u.value("id", "");
        const std::string upn = u.value("userPrincipalName", "?");
        const auto methods = graph_get_all(
            "https://graph.microsoft.com/v1.0/users/" + id + "/authentication/methods",
            bearer_token);

        // Every user has a password method. Email is only for password reset,
        // not a second factor. Anything else counts as a registered MFA method.
        bool has_mfa = false;
        for (const auto& m : methods) {
            const std::string type = m.value("@odata.type", "");
            if (type != "#microsoft.graph.passwordAuthenticationMethod" &&
                type != "#microsoft.graph.emailAuthenticationMethod") {
                has_mfa = true;
                break;
            }
        }
        if (!has_mfa) {
            findings.push_back({
                Severity::Medium, "MFA", upn, "No MFA method registered",
                "A stolen password alone is enough to sign in as this user."});
        }
    }
    return findings;
}
