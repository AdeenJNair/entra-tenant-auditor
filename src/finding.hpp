#pragma once
#include <string>

enum class Severity { Low, Medium, High };

inline const char* to_string(Severity s) {
    switch (s) {
        case Severity::High:   return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low:    return "LOW";
    }
    return "?";  // unreachable, keeps compilers quiet
}

// One audit result. Every module produces a list of these, so console and
// CSV/HTML reporting only ever deal with one shape.
struct Finding {
    Severity severity;
    std::string category;  // e.g. "MFA", "Guest"
    std::string subject;   // who/what it is about, e.g. a UPN
    std::string detail;    // what we saw
    std::string why;       // one-line "why this matters"
};
