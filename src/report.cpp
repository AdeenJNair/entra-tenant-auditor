#include "report.hpp"

#include <fstream>
#include <stdexcept>

namespace {

// CSV: wrap the field in quotes and double any quote inside it.
// Also defuse "CSV injection": Excel treats a cell starting with = + - @ as a
// formula. User-controlled text (display names) could run one, so we prefix
// such cells with a single quote.
std::string csv_field(const std::string& s) {
    std::string out = "\"";
    if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@')) out += '\'';
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

// HTML: any text from the tenant must be escaped, or a display name like
// "<script>..." would run in the browser that opens the report.
std::string html_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;
        }
    }
    return out;
}

const char* severity_color(Severity s) {
    switch (s) {
        case Severity::High:   return "#c62828";
        case Severity::Medium: return "#ef6c00";
        case Severity::Low:    return "#2e7d32";
    }
    return "#000";
}

}  // namespace

void write_csv(const std::string& path, const std::vector<Finding>& findings) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot write " + path);

    out << "severity,category,subject,detail,why\n";
    for (const auto& f : findings) {
        out << csv_field(to_string(f.severity)) << ',' << csv_field(f.category) << ','
            << csv_field(f.subject) << ',' << csv_field(f.detail) << ','
            << csv_field(f.why) << '\n';
    }
}

void write_html(const std::string& path, const std::vector<Finding>& findings,
                const std::string& tenant_id) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot write " + path);

    out << "<!doctype html><html><head><meta charset=\"utf-8\">"
           "<title>Entra Tenant Security Audit</title><style>"
           "body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}"
           "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}th{background:#eee}"
           ".sev{color:#fff;font-weight:bold;text-align:center}"
           "</style></head><body><h1>Entra Tenant Security Audit</h1><p>Tenant: "
        << html_escape(tenant_id) << " &middot; " << findings.size() << " finding(s)</p>"
        << "<table><tr><th>Severity</th><th>Category</th><th>Subject</th><th>Detail</th>"
           "<th>Why it matters</th></tr>";
    for (const auto& f : findings) {
        out << "<tr><td class=\"sev\" style=\"background:" << severity_color(f.severity) << "\">"
            << to_string(f.severity) << "</td><td>" << html_escape(f.category) << "</td><td>"
            << html_escape(f.subject) << "</td><td>" << html_escape(f.detail) << "</td><td>"
            << html_escape(f.why) << "</td></tr>";
    }
    out << "</table></body></html>\n";
}
