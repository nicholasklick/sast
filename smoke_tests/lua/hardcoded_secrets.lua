-- Hardcoded Secrets vulnerabilities in Lua

-- Test 1: Hardcoded API key
local API_KEY = "sk_live_1234567890abcdef"

-- Test 2: Hardcoded password
local DB_PASSWORD = "super_secret_password_123"

-- Test 3: Hardcoded AWS credentials
local AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
local AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

-- Test 4: Hardcoded JWT secret
local JWT_SECRET = "my-super-secret-jwt-key-12345"

-- Test 5: Database connection string with password
function get_connection()
    -- VULNERABLE: Password in connection string
    local connection_string = "mysql://admin:password123@localhost/mydb"
    return connect(connection_string)
end

-- Test 6: Hardcoded private key
local PRIVATE_KEY = [[
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----
]]

-- Test 7: API token in header
function make_api_call(endpoint)
    local httpc = require("resty.http").new()
    -- VULNERABLE: Hardcoded bearer token
    return httpc:request_uri(endpoint, {
        headers = {
            ["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        }
    })
end

-- Test 8: Hardcoded encryption key
local ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"

-- Test 9: OAuth client secret
local OAUTH_CONFIG = {
    client_id = "my-app-id",
    client_secret = "super_secret_oauth_client_secret"  -- VULNERABLE
}

-- Test 10: Slack webhook URL
local SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

-- Test 11: GitHub token
local GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

-- Test 12: Stripe API key
local STRIPE_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

-- Test 13: SendGrid API key
local SENDGRID_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

-- Test 14: Firebase config
local FIREBASE_CONFIG = {
    apiKey = "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    authDomain = "myapp.firebaseapp.com"
}

-- Test 15: Basic auth credentials
function connect_with_auth(url)
    local http = require("socket.http")
    -- VULNERABLE: Hardcoded basic auth
    local auth = "admin:admin123"
    http.request{
        url = url,
        headers = {
            ["Authorization"] = "Basic " .. encode_base64(auth)
        }
    }
end

-- Test 16: SSH private key path
local SSH_KEY_CONTENT = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA..."

-- Test 17: Twilio credentials
local TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
local TWILIO_AUTH_TOKEN = "your_auth_token_here"

-- Test 18: Redis password
local REDIS_CONFIG = {
    host = "localhost",
    port = 6379,
    password = "redis_secret_password"  -- VULNERABLE
}

function encode_base64(str)
    return str -- stub
end

function connect(str)
    return {} -- stub
end
