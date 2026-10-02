#pragma once
#include <nlohmann/json.hpp>

#include <ctime>
#include <string>
#include <vector>

#include "finding.hpp"

// `users` is the JSON array returned by GET /users.
std::vector<Finding> audit_guests(const std::vector<nlohmann::json>& users);

// Calls GET /users/{id}/authentication/methods once per enabled user.
std::vector<Finding> audit_mfa(const std::vector<nlohmann::json>& users,
                               const std::string& bearer_token);

// Lists tenant-wide directory role assignments (needs RoleManagement.Read.Directory)
// and reports every holder of a role Microsoft marks as privileged.
std::vector<Finding> audit_roles(const std::string& bearer_token);

// Cross-check: a no-MFA finding for an account that also holds a privileged
// role is far more dangerous, so raise it to HIGH.
void escalate_privileged_without_mfa(std::vector<Finding>& findings);

// Needs Policy.Read.All. Flags report-only/disabled policies, policy exclusions,
// and a tenant with no enforced policy at all. `users` resolves excluded user
// ids to names.
std::vector<Finding> audit_conditional_access(const std::vector<nlohmann::json>& users,
                                              const std::string& bearer_token);

// Needs DeviceManagementManagedDevices.Read.All (Intune).
std::vector<Finding> audit_devices(const std::string& bearer_token, int stale_days = 30);

// Pure analysis (no network), split out so it can be tested with fake JSON.
std::vector<Finding> analyse_conditional_access(const std::vector<nlohmann::json>& policies,
                                                const std::vector<nlohmann::json>& users);
std::vector<Finding> analyse_devices(const std::vector<nlohmann::json>& devices,
                                     std::time_t now, int stale_days);
