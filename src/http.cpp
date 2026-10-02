#include "http.hpp"

#include <curl/curl.h>

#include <memory>
#include <stdexcept>
#include <vector>

namespace {

// Called by libcurl for each chunk of the response body.
size_t write_callback(char* data, size_t size, size_t nmemb, void* userp) {
    auto* buffer = static_cast<std::string*>(userp);
    const size_t bytes = size * nmemb;
    buffer->append(data, bytes);
    return bytes;
}

// RAII owner of a CURL* (see Step 1 notes).
class CurlHandle {
public:
    CurlHandle() : handle_(curl_easy_init()) {
        if (!handle_) throw std::runtime_error("curl_easy_init failed");
    }
    ~CurlHandle() { curl_easy_cleanup(handle_); }
    CurlHandle(const CurlHandle&) = delete;
    CurlHandle& operator=(const CurlHandle&) = delete;
    CURL* get() const { return handle_; }
private:
    CURL* handle_;
};

// curl_global_init must run once per program; a function-local static does
// that on first use, and its destructor runs the cleanup at program exit.
struct CurlGlobal {
    CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobal() { curl_global_cleanup(); }
};
void ensure_curl_initialised() { static CurlGlobal g; (void)g; }

// Owns a curl_slist (curl's linked list of header lines) and frees it.
class HeaderList {
public:
    HeaderList() = default;
    ~HeaderList() { curl_slist_free_all(list_); }
    HeaderList(const HeaderList&) = delete;
    HeaderList& operator=(const HeaderList&) = delete;
    void add(const std::string& line) {
        // curl_slist_append copies the string, so `line` may die afterwards.
        curl_slist* next = curl_slist_append(list_, line.c_str());
        if (!next) throw std::runtime_error("curl_slist_append failed");
        list_ = next;
    }
    curl_slist* get() const { return list_; }
private:
    curl_slist* list_ = nullptr;
};

// Runs the prepared request and fills in status + body.
HttpResponse perform(CurlHandle& curl) {
    HttpResponse response;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 30L);  // never hang forever

    const CURLcode rc = curl_easy_perform(curl.get());
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(rc));

    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &response.status);
    return response;
}

}  // namespace

std::string url_encode(const std::string& value) {
    ensure_curl_initialised();
    CurlHandle curl;
    // curl_easy_escape returns a malloc'd char* that WE must release with
    // curl_free. unique_ptr with a custom deleter makes that automatic.
    std::unique_ptr<char, decltype(&curl_free)> escaped(
        curl_easy_escape(curl.get(), value.c_str(), static_cast<int>(value.size())),
        &curl_free);
    if (!escaped) throw std::runtime_error("curl_easy_escape failed");
    return std::string(escaped.get());
}

HttpResponse http_post_form(const std::string& url, const std::string& form_body) {
    ensure_curl_initialised();
    CurlHandle curl;
    HeaderList headers;
    headers.add("Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    // COPYPOSTFIELDS makes curl keep its own copy of the body.
    curl_easy_setopt(curl.get(), CURLOPT_COPYPOSTFIELDS, form_body.c_str());
    return perform(curl);
}

HttpResponse http_get(const std::string& url, const std::string& bearer_token) {
    ensure_curl_initialised();
    CurlHandle curl;
    HeaderList headers;
    headers.add("Authorization: Bearer " + bearer_token);
    headers.add("Accept: application/json");

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    return perform(curl);
}
