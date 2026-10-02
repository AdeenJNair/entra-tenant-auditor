#pragma once
#include <string>

// Safety checks run BEFORE any audit call:
//  1. the token must belong to the lab tenant we expect (never a client tenant)
//  2. the token must carry no write permissions (this tool is read-only)
// Prints the permissions the token holds. Throws std::runtime_error to refuse.
void enforce_lab_guardrail(const std::string& access_token,
                           const std::string& expected_tenant_id);
