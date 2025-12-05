-- Authentication vulnerabilities in Lua

local crypto = require("crypto")

-- Test 1: Hardcoded credentials
function authenticate(username, password)
    -- VULNERABLE: Hardcoded credentials
    if username == "admin" and password == "admin123" then
        return true
    end
    return false
end

-- Test 2: Weak password hashing (MD5)
function hash_password(password)
    -- VULNERABLE: MD5 is cryptographically broken
    return crypto.digest("md5", password)
end

-- Test 3: No salt in password hash
function hash_password_unsalted(password)
    -- VULNERABLE: No salt
    return crypto.digest("sha256", password)
end

-- Test 4: Timing attack vulnerable comparison
function verify_password(input_hash, stored_hash)
    -- VULNERABLE: Non-constant time comparison
    return input_hash == stored_hash
end

-- Test 5: Predictable session token
function generate_session_token(user_id)
    -- VULNERABLE: Predictable token
    return tostring(user_id) .. "_" .. tostring(os.time())
end

-- Test 6: Weak password validation
function validate_password(password)
    -- VULNERABLE: Weak password requirements
    return #password >= 4
end

-- Test 7: Password in logs
function login_with_logging(username, password)
    -- VULNERABLE: Logging password
    print("Login attempt: " .. username .. " / " .. password)
    return check_credentials(username, password)
end

-- Test 8: Token stored in cookie without flags
function set_session_cookie(token)
    -- VULNERABLE: Missing HttpOnly, Secure flags
    ngx.header["Set-Cookie"] = "session=" .. token
end

-- Test 9: Weak JWT implementation
function create_jwt(user_id)
    -- VULNERABLE: Weak secret
    local secret = "secret"
    local header = '{"alg":"HS256","typ":"JWT"}'
    local payload = '{"user_id":' .. user_id .. '}'
    -- Simplified JWT (vulnerable)
    return encode_base64(header) .. "." .. encode_base64(payload) .. ".signature"
end

-- Test 10: No brute force protection
function login(username, password)
    -- VULNERABLE: No rate limiting or lockout
    return check_credentials(username, password)
end

-- Test 11: Password reset token predictable
function generate_reset_token(email)
    -- VULNERABLE: Predictable reset token
    math.randomseed(os.time())
    return tostring(math.random(100000, 999999))
end

-- Test 12: Remember me token weak
function create_remember_token(user_id)
    -- VULNERABLE: Weak remember me token
    return encode_base64(user_id .. ":" .. os.time())
end

-- Test 13: Session fixation
function login_session(username, password, session)
    if check_credentials(username, password) then
        -- VULNERABLE: No session regeneration
        session.user = username
        session.authenticated = true
        return true
    end
    return false
end

-- Test 14: Weak PBKDF2 iterations
function derive_key(password, salt)
    -- VULNERABLE: Too few iterations
    return crypto.pbkdf2("sha256", password, salt, 100, 32)
end

-- Test 15: Basic auth over HTTP
function basic_auth_check()
    local auth_header = ngx.req.get_headers()["Authorization"]
    if auth_header then
        -- VULNERABLE: Basic auth transmitted (potentially over HTTP)
        local encoded = auth_header:match("Basic%s+(.+)")
        local decoded = ngx.decode_base64(encoded)
        local username, password = decoded:match("([^:]+):(.+)")
        return check_credentials(username, password)
    end
    return false
end

-- Helper functions (stubs)
function check_credentials(username, password)
    return false
end

function encode_base64(str)
    return str
end
