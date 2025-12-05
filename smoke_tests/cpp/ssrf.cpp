// SSRF (Server-Side Request Forgery) vulnerabilities in C++
#include <iostream>
#include <string>
#include <curl/curl.h>

// Test 1: Direct URL from user input
void fetch_url(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: User-controlled URL
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 2: URL parameter used in request
void fetch_image(const std::string& image_url) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: image_url from user
        curl_easy_setopt(curl, CURLOPT_URL, image_url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 3: Partial URL construction
void fetch_from_host(const std::string& hostname) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: hostname from user
        std::string url = "http://" + hostname + "/api/data";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 4: Port injection
void fetch_with_port(const std::string& host, const std::string& port) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: port from user, can access internal services
        std::string url = "http://internal-server:" + port + "/";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 5: URL in redirect
void handle_redirect(const std::string& redirect_url) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: Following redirects to user-controlled URL
        curl_easy_setopt(curl, CURLOPT_URL, redirect_url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 6: DNS rebinding vulnerability
void fetch_external(const std::string& domain) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: DNS can resolve to internal IP after validation
        std::string url = "http://" + domain + "/data";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 7: File protocol SSRF
void fetch_resource(const std::string& resource_url) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: Could be file:///etc/passwd
        curl_easy_setopt(curl, CURLOPT_URL, resource_url.c_str());
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_ALL);  // Allows file://
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 8: Webhook URL
void send_webhook(const std::string& webhook_url, const std::string& data) {
    CURL* curl = curl_easy_init();
    if (curl) {
        // VULNERABLE: webhook_url from user configuration
        curl_easy_setopt(curl, CURLOPT_URL, webhook_url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
