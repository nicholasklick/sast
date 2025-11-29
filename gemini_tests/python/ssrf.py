import requests

# Simulate user input specifying a URL to fetch
# An attacker could provide a URL to an internal service
user_provided_url = "http://127.0.0.1/admin"
# Or a metadata service in a cloud environment
# user_provided_url = "http://169.254.169.254/latest/meta-data/"

# --- VULNERABLE CODE ---
try:
    # The application fetches content from a URL provided by the user
    response = requests.get(user_provided_url, timeout=5) # CWE-918: Server-Side Request Forgery (SSRF)
    print("Response from URL:")
    print(response.text)
except requests.exceptions.RequestException as e:
    print(f"Could not fetch URL: {e}")
# -----------------------
