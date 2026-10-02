#include "audit.hpp"

#include <map>
#include <set>
#include <utility>

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

std::vector<Finding> audit_roles(const std::string& bearer_token) {
    // Step 1: role id -> display name. Assignments only carry the id, so we need
    // this lookup table to print "Global Administrator".
    const auto definitions = graph_get_all(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
        "?$select=id,displayName",
        bearer_token);
    std::map<std::string, std::string> roles;
    for (const auto& d : definitions)
        roles[d.value("id", "")] = d.value("displayName", "?");

    // The "isPrivileged" flag exists only in Graph beta, so we keep our own list.
    // Roles that can take over the tenant or other admins:
    const std::set<std::string> critical = {
        "Global Administrator", "Privileged Role Administrator",
        "Privileged Authentication Administrator"};
    // Powerful, but narrower in scope:
    const std::set<std::string> privileged = {
        "User Administrator", "Authentication Administrator", "Helpdesk Administrator",
        "Exchange Administrator", "SharePoint Administrator", "Security Administrator",
        "Conditional Access Administrator", "Application Administrator",
        "Cloud Application Administrator", "Intune Administrator",
        "Hybrid Identity Administrator", "Groups Administrator"};

    // Step 2: who holds what. $expand=principal embeds the user/group/app
    // object, saving one extra request per assignment.
    const auto assignments = graph_get_all(
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        "?$expand=principal",
        bearer_token);

    std::vector<Finding> findings;
    for (const auto& a : assignments) {
        const auto it = roles.find(a.value("roleDefinitionId", ""));
        if (it == roles.end()) continue;
        const std::string& role_name = it->second;
        const bool is_critical = critical.count(role_name) > 0;
        if (!is_critical && privileged.count(role_name) == 0) continue;  // not on our lists

        const auto principal = a.value("principal", nlohmann::json::object());
        const std::string who = principal.value(
            "userPrincipalName", principal.value("displayName", "?"));
        findings.push_back({
            is_critical ? Severity::High : Severity::Medium,
            "Privileged role", who, "Holds " + role_name,
            "Privileged roles can change the tenant itself: keep the list short and protected by MFA."});
    }
    return findings;
}

void escalate_privileged_without_mfa(std::vector<Finding>& findings) {
    std::set<std::string> privileged;
    for (const auto& f : findings)
        if (f.category == "Privileged role") privileged.insert(f.subject);

    for (auto& f : findings) {
        if (f.category == "MFA" && privileged.count(f.subject)) {
            f.severity = Severity::High;
            f.detail += " and holds a privileged role";
            f.why = "An admin protected only by a password is the shortest path to full tenant takeover.";
        }
    }
}
