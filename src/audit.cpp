#include "audit.hpp"

#include <ctime>
#include <map>
#include <set>
#include <utility>

#include "graph.hpp"
#include "time_util.hpp"

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

namespace {

// Returns j[key] if it is an object, else an empty object. Graph sends null for
// parts of a policy that aren't configured, and .value() would throw on null.
nlohmann::json object_at(const nlohmann::json& j, const char* key) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_object()) ? *it : nlohmann::json::object();
}

std::vector<std::string> strings_at(const nlohmann::json& j, const char* key) {
    std::vector<std::string> out;
    const auto it = j.find(key);
    if (it != j.end() && it->is_array())
        for (const auto& v : *it)
            if (v.is_string()) out.push_back(v.get<std::string>());
    return out;
}

// "a, b, c" with ids replaced by names where we know them.
std::string describe(const std::vector<std::string>& ids,
                     const std::map<std::string, std::string>& names) {
    std::string out;
    for (const auto& id : ids) {
        const auto it = names.find(id);
        out += (out.empty() ? "" : ", ") + (it == names.end() ? id : it->second);
    }
    return out;
}

}  // namespace

std::vector<Finding> analyse_conditional_access(const std::vector<nlohmann::json>& policies,
                                                const std::vector<nlohmann::json>& users) {
    std::map<std::string, std::string> user_names;
    for (const auto& u : users) user_names[u.value("id", "")] = u.value("userPrincipalName", "?");
    const std::map<std::string, std::string> no_names;  // groups/roles/apps stay as ids

    std::vector<Finding> findings;
    bool any_enforced = false;
    for (const auto& p : policies) {
        const std::string name  = p.value("displayName", "?");
        const std::string state = p.value("state", "");

        if (state == "enabled") {
            any_enforced = true;
        } else if (state == "enabledForReportingButNotEnforced") {
            findings.push_back({Severity::Medium, "Conditional Access", name,
                "Report-only: evaluated and logged, but NOT enforced",
                "A report-only policy blocks nothing, so people may assume they are protected when they are not."});
        } else {
            findings.push_back({Severity::Low, "Conditional Access", name, "Policy is disabled",
                "A disabled policy protects nothing: delete it or finish and enable it."});
            continue;  // exclusions of a disabled policy don't matter
        }

        const auto users_cond = object_at(object_at(p, "conditions"), "users");
        const auto apps_cond  = object_at(object_at(p, "conditions"), "applications");
        std::string excluded;
        const auto add = [&](const char* label, const std::string& text) {
            if (!text.empty()) excluded += (excluded.empty() ? "" : "; ") + std::string(label) + ": " + text;
        };
        add("users",  describe(strings_at(users_cond, "excludeUsers"), user_names));
        add("groups", describe(strings_at(users_cond, "excludeGroups"), no_names));
        add("roles",  describe(strings_at(users_cond, "excludeRoles"), no_names));
        add("apps",   describe(strings_at(apps_cond, "excludeApplications"), no_names));
        if (!excluded.empty()) {
            findings.push_back({Severity::Medium, "Conditional Access", name, "Excludes " + excluded,
                "Every exclusion is a hole in the policy, and attackers look for excluded accounts first."});
        }
    }
    if (!any_enforced) {
        findings.push_back({Severity::High, "Conditional Access", "(tenant)",
            "No Conditional Access policy is enforced",
            "Without enforced policies, sign-ins are not protected by MFA, device or location rules."});
    }
    return findings;
}

std::vector<Finding> audit_conditional_access(const std::vector<nlohmann::json>& users,
                                              const std::string& bearer_token) {
    return analyse_conditional_access(
        graph_get_all("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                      bearer_token),
        users);
}

std::vector<Finding> analyse_devices(const std::vector<nlohmann::json>& devices,
                                     std::time_t now, int stale_days) {
    std::vector<Finding> findings;
    for (const auto& d : devices) {
        const std::string name  = d.value("deviceName", "?");
        const std::string owner = d.value("userPrincipalName", "no primary user");
        const std::string state = d.value("complianceState", "unknown");
        const std::string who   = name + " (" + owner + ")";

        if (state == "noncompliant") {
            findings.push_back({Severity::Medium, "Device", who, "Non-compliant with Intune policy",
                "The device misses your security baseline (e.g. encryption or patches) yet may still reach company data."});
        } else if (state != "compliant") {
            findings.push_back({Severity::Low, "Device", who, "Compliance state: " + state,
                "Compliance isn't confirmed, so you can't tell whether this device meets your baseline."});
        }

        const auto last = parse_utc_timestamp(d.value("lastSyncDateTime", ""));
        if (last) {
            const long days = static_cast<long>((now - *last) / 86400);
            if (days > stale_days) {
                findings.push_back({Severity::Medium, "Device", who,
                    "Last check-in " + std::to_string(days) + " days ago",
                    "A device that stopped checking in may be lost, stolen or unmanaged, with stale compliance data."});
            }
        }
    }
    return findings;
}

std::vector<Finding> audit_devices(const std::string& bearer_token, int stale_days) {
    return analyse_devices(
        graph_get_all(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
            "?$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime",
            bearer_token),
        std::time(nullptr), stale_days);
}
