// Minimal test runner: no framework, so every line is explainable.
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

#include "../src/audit.hpp"
#include "../src/guard.hpp"
#include "../src/time_util.hpp"

using nlohmann::json;
static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { ++failures; std::cerr << "FAIL line " << __LINE__ << ": " #cond "\n"; } } while (0)

// Build a fake (unsigned) JWT: header.payload.signature, payload base64url-encoded.
static std::string b64url(const std::string& s) {
    static const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out; unsigned v = 0; int bits = 0;
    for (unsigned char c : s) { v = (v << 8) | c; bits += 8; while (bits >= 6) { out += a[(v >> (bits - 6)) & 63]; bits -= 6; } }
    if (bits > 0) out += a[(v << (6 - bits)) & 63];
    return out;
}
static std::string fake_jwt(const json& claims) { return "e30." + b64url(claims.dump()) + ".sig"; }

static bool guard_throws(const json& claims, const std::string& expected) {
    try { enforce_lab_guardrail(fake_jwt(claims), expected); return false; }
    catch (const std::exception&) { return true; }
}

int main() {
    // --- time parsing: 2026-10-02T10:12:28Z == 1790935948 (checked against `date -u`)
    CHECK(parse_utc_timestamp("2026-10-02T10:12:28Z").value() == 1790935948);
    CHECK(parse_utc_timestamp("1970-01-01T00:00:00Z").value() == 0);
    CHECK(parse_utc_timestamp("2024-02-29T00:00:00Z").value() == 1709164800);  // leap day
    CHECK(!parse_utc_timestamp("garbage").has_value());

    // --- guardrail
    CHECK(!guard_throws({{"tid", "lab"}, {"roles", {"User.Read.All"}}}, "lab"));
    CHECK(guard_throws({{"tid", "client-tenant"}, {"roles", {"User.Read.All"}}}, "lab"));
    CHECK(guard_throws({{"tid", "lab"}, {"roles", {"User.ReadWrite.All"}}}, "lab"));
    CHECK(guard_throws({{"tid", "lab"}}, "other"));
    CHECK(!guard_throws({{"tid", "lab"}}, "lab"));  // no roles claim: allowed, prints (none)

    // --- conditional access
    const std::vector<json> users = {{{"id", "u1"}, {"userPrincipalName", "alice@lab"}}};
    {
        const auto f = analyse_conditional_access({}, users);
        CHECK(f.size() == 1 && f[0].severity == Severity::High);  // nothing enforced
    }
    {
        const std::vector<json> policies = {
            {{"displayName", "Require MFA"}, {"state", "enabled"},
             {"conditions", {{"users", {{"excludeUsers", {"u1", "u-unknown"}}, {"excludeGroups", json::array()}}},
                             {"applications", nullptr}}},
             {"grantControls", nullptr}},
            {{"displayName", "Block legacy"}, {"state", "enabledForReportingButNotEnforced"}},
            {{"displayName", "Old"}, {"state", "disabled"},
             {"conditions", {{"users", {{"excludeUsers", {"u1"}}}}}}}};
        const auto f = analyse_conditional_access(policies, users);
        int exclusion = 0, report_only = 0, disabled = 0, high = 0;
        for (const auto& x : f) {
            if (x.detail.rfind("Excludes", 0) == 0) { ++exclusion; CHECK(x.detail.find("alice@lab") != std::string::npos); CHECK(x.detail.find("u-unknown") != std::string::npos); }
            if (x.detail.rfind("Report-only", 0) == 0) ++report_only;
            if (x.detail == "Policy is disabled") ++disabled;
            if (x.severity == Severity::High) ++high;
        }
        CHECK(exclusion == 1);   // disabled policy's exclusions are ignored
        CHECK(report_only == 1 && disabled == 1 && high == 0);  // one enforced policy exists
    }

    // --- devices (now = 2026-10-02T10:12:28Z)
    {
        const std::time_t now = 1790935948;
        const std::vector<json> devices = {
            {{"deviceName", "ok"},   {"complianceState", "compliant"},    {"lastSyncDateTime", "2026-10-01T00:00:00Z"}},
            {{"deviceName", "bad"},  {"complianceState", "noncompliant"}, {"lastSyncDateTime", "2026-10-01T00:00:00Z"}},
            {{"deviceName", "old"},  {"complianceState", "compliant"},    {"lastSyncDateTime", "2026-08-01T00:00:00Z"}},
            {{"deviceName", "edge"}, {"complianceState", "compliant"},    {"lastSyncDateTime", "2026-09-02T10:12:28Z"}}};  // exactly 30 days
        const auto f = analyse_devices(devices, now, 30);
        CHECK(f.size() == 2);  // "bad" (noncompliant) and "old" (stale); "edge" is not > 30
    }

    if (failures == 0) std::cout << "All tests passed\n";
    return failures == 0 ? 0 : 1;
}
