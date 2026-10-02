#pragma once
#include <ctime>
#include <optional>
#include <string>

// Parses Graph timestamps like "2026-09-01T12:34:56Z" (UTC) into Unix seconds.
// Returns nullopt if the text isn't in that shape.
std::optional<std::time_t> parse_utc_timestamp(const std::string& text);
