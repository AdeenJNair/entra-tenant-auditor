#include "graph.hpp"

#include <stdexcept>

#include "http.hpp"

std::vector<nlohmann::json> graph_get_all(const std::string& url,
                                          const std::string& bearer_token) {
    std::vector<nlohmann::json> items;
    std::string next = url;

    // Graph returns big lists in pages. Each page may contain
    // "@odata.nextLink": the full URL of the next page. No link = last page.
    while (!next.empty()) {
        const HttpResponse resp = http_get(next, bearer_token);
        const nlohmann::json page = nlohmann::json::parse(resp.body);

        if (resp.status != 200) {
            const auto& err = page.value("error", nlohmann::json::object());
            throw std::runtime_error(
                "Graph request failed (HTTP " + std::to_string(resp.status) + "): " +
                err.value("code", "unknown") + " - " + err.value("message", "no message"));
        }

        for (const auto& item : page.at("value")) items.push_back(item);
        next = page.value("@odata.nextLink", "");
    }
    return items;
}
