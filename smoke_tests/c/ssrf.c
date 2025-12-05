// SSRF (Server-Side Request Forgery) Test Cases

#include <stdio.h>
#include <curl/curl.h>

// Test 1: Making HTTP request to user-provided URL
void fetch_url(const char *url) {
    CURL *curl = curl_easy_init();
    if(curl) {
        // VULNERABLE: Fetching user-controlled URL
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Test 2: Downloading file from user input
void download_image(const char *image_url) {
    CURL *curl = curl_easy_init();
    // VULNERABLE: Could access internal resources
    curl_easy_setopt(curl, CURLOPT_URL, image_url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

// Test 3: Webhook callback
void trigger_webhook(const char *callback_url, const char *data) {
    CURL *curl = curl_easy_init();
    // VULNERABLE: User-controlled callback URL
    curl_easy_setopt(curl, CURLOPT_URL, callback_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

// Test 4: URL with user-provided parameters
void fetch_resource(const char *host, const char *path) {
    char url[512];
    // VULNERABLE: host and path from user input
    snprintf(url, sizeof(url), "http://%s/%s", host, path);

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

// Test 5: API request to external service
void fetch_external_api(const char *api_endpoint) {
    CURL *curl = curl_easy_init();
    // VULNERABLE: api_endpoint could point to internal services
    curl_easy_setopt(curl, CURLOPT_URL, api_endpoint);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
