#include "token.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

#include "http.hpp"

AccessToken fetch_token(const std::string& tenant_id,
                        const std::string& client_id,
                        const std::string& client_secret) {
    const std::string url =
        "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/token";

    // Every value is percent-encoded: secrets often contain characters like
    // '~', '+' or '&' that would otherwise corrupt the form body.
    const std::string form =
        "grant_type=client_credentials"
        "&client_id=" + url_encode(client_id) +
        "&client_secret=" + url_encode(client_secret) +
        "&scope=" + url_encode("https://graph.microsoft.com/.default");

    const HttpResponse resp = http_post_form(url, form);

    // The whole body is buffered by now, so the JSON parser sees complete text.
    // parse() throws on malformed JSON; we let that surface as an error.
    const nlohmann::json json = nlohmann::json::parse(resp.body);

    if (resp.status != 200) {
        // Azure AD errors look like {"error":"invalid_client","error_description":"..."}
        throw std::runtime_error(
            "Token request failed (HTTP " + std::to_string(resp.status) + "): " +
            json.value("error", "unknown_error") + " - " +
            json.value("error_description", "no description"));
    }

    AccessToken token;
    token.value = json.at("access_token").get<std::string>();
    token.expires_in = json.at("expires_in").get<int>();
    return token;
}
