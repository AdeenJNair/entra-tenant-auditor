#include "time_util.hpp"

#include <cstdio>

namespace {

// Days since 1970-01-01 for a calendar date (proleptic Gregorian).
// Counting years from March makes the leap day the LAST day of the year,
// which turns the leap-year rule into plain integer arithmetic.
long long days_from_civil(int y, int m, int d) {
    if (m <= 2) y -= 1;
    const long long era = (y >= 0 ? y : y - 399) / 400;   // 400-year cycles
    const int yoe = static_cast<int>(y - era * 400);      // year within cycle
    const int mp = m > 2 ? m - 3 : m + 9;                 // March = 0
    const int doy = (153 * mp + 2) / 5 + d - 1;           // day within year
    const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

}  // namespace

std::optional<std::time_t> parse_utc_timestamp(const std::string& text) {
    int y, mo, d, h, mi, s;
    // sscanf returns how many fields it filled; we need all six.
    if (std::sscanf(text.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6)
        return std::nullopt;
    return static_cast<std::time_t>(days_from_civil(y, mo, d) * 86400LL + h * 3600 + mi * 60 + s);
}
