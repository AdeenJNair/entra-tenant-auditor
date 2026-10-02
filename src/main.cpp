// Step 1: prove the toolchain works with ONE successful HTTPS GET.
#include <curl/curl.h>

#include <iostream>
#include <string>

// libcurl calls this function every time a chunk of the response body arrives.
// It may be called many times for one response, so we APPEND to the buffer.
static size_t write_callback(char* data, size_t size, size_t nmemb, void* userp) {
    auto* buffer = static_cast<std::string*>(userp);
    const size_t bytes = size * nmemb;
    buffer->append(data, bytes);
    return bytes;  // returning anything other than `bytes` tells curl "abort"
}

// RAII wrapper: constructor acquires the curl handle, destructor releases it.
class CurlHandle {
public:
    CurlHandle() : handle_(curl_easy_init()) {}
    ~CurlHandle() { if (handle_) curl_easy_cleanup(handle_); }
    CurlHandle(const CurlHandle&) = delete;             // no copying: two owners
    CurlHandle& operator=(const CurlHandle&) = delete;  // would double-free
    CURL* get() const { return handle_; }
private:
    CURL* handle_;
};

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    {
        CurlHandle curl;
        if (!curl.get()) { std::cerr << "curl_easy_init failed\n"; return 1; }

        std::string body;
        curl_easy_setopt(curl.get(), CURLOPT_URL, "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);

        CURLcode rc = curl_easy_perform(curl.get());
        if (rc != CURLE_OK) {
            std::cerr << "request failed: " << curl_easy_strerror(rc) << "\n";
            return 1;
        }

        long status = 0;
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
        std::cout << "HTTP " << status << ", " << body.size() << " bytes\n"
                  << body.substr(0, 200) << "...\n";
    }  // CurlHandle destroyed here, BEFORE global cleanup

    curl_global_cleanup();
    return 0;
}
