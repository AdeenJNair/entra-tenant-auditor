#pragma once
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

// GETs a Graph collection and follows @odata.nextLink until every page is
// read. `url` is a full URL. Returns the concatenated "value" arrays.
// Throws std::runtime_error on any non-200 reply, with Graph's error text.
std::vector<nlohmann::json> graph_get_all(const std::string& url,
                                          const std::string& bearer_token);
