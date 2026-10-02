#pragma once
#include <string>
#include <vector>

#include "finding.hpp"

// Both functions throw std::runtime_error if the file cannot be written.
void write_csv(const std::string& path, const std::vector<Finding>& findings);
void write_html(const std::string& path, const std::vector<Finding>& findings,
                const std::string& tenant_id, const std::vector<std::string>& skipped);
