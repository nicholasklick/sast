# --- VULNERABLE CODE ---
# Hardcoded API key, password, or other secret
API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz1234567890" # CWE-798: Use of Hard-coded Credentials
PASSWORD = "admin_password_123!" # CWE-798
# -----------------------

def connect_to_service():
    print(f"Connecting with API Key: {API_KEY}")

def login():
    print(f"Logging in with password: {PASSWORD}")

connect_to_service()
login()
