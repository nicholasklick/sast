-- Weak Cryptography vulnerabilities in Lua

local crypto = require("crypto") -- LuaCrypto
local openssl = require("openssl")

-- Test 1: MD5 for password hashing
function hash_password_md5(password)
    -- VULNERABLE: MD5 is broken
    return crypto.digest("md5", password)
end

-- Test 2: SHA1 for password hashing
function hash_password_sha1(password)
    -- VULNERABLE: SHA1 is weak for passwords
    return crypto.digest("sha1", password)
end

-- Test 3: Unsalted hash
function hash_without_salt(password)
    -- VULNERABLE: No salt
    return crypto.digest("sha256", password)
end

-- Test 4: DES encryption
function encrypt_des(data, key)
    -- VULNERABLE: DES is weak
    return crypto.encrypt("des", data, key)
end

-- Test 5: ECB mode
function encrypt_ecb(data, key)
    -- VULNERABLE: ECB mode leaks patterns
    return crypto.encrypt("aes-128-ecb", data, key)
end

-- Test 6: Weak key generation
function generate_weak_key()
    -- VULNERABLE: Predictable key from time
    math.randomseed(os.time())
    local key = ""
    for i = 1, 16 do
        key = key .. string.char(math.random(0, 255))
    end
    return key
end

-- Test 7: RC4 cipher
function encrypt_rc4(data, key)
    -- VULNERABLE: RC4 is broken
    return crypto.encrypt("rc4", data, key)
end

-- Test 8: Static IV
function encrypt_with_static_iv(data, key)
    -- VULNERABLE: Static/predictable IV
    local iv = "0000000000000000"
    return crypto.encrypt("aes-128-cbc", data, key, iv)
end

-- Test 9: Weak random for crypto
function generate_token()
    -- VULNERABLE: math.random is not cryptographically secure
    math.randomseed(os.time())
    local token = ""
    for i = 1, 32 do
        token = token .. string.format("%02x", math.random(0, 255))
    end
    return token
end

-- Test 10: Password comparison timing attack
function verify_password(input, stored)
    -- VULNERABLE: Non-constant time comparison
    return input == stored
end

-- Test 11: Weak PBKDF iterations
function derive_key(password, salt)
    -- VULNERABLE: Too few iterations
    return crypto.pbkdf2("sha256", password, salt, 100, 32)
end

-- Test 12: Hardcoded salt
function hash_with_hardcoded_salt(password)
    -- VULNERABLE: Same salt for all users
    local salt = "static_salt_value"
    return crypto.digest("sha256", password .. salt)
end

-- Test 13: Blowfish with small key
function encrypt_blowfish(data, key)
    -- VULNERABLE: Blowfish with weak key
    if #key < 16 then
        -- Using short key
    end
    return crypto.encrypt("bf", data, key)
end

-- Test 14: Base64 as "encryption"
function pseudo_encrypt(data)
    -- VULNERABLE: Base64 is not encryption
    local mime = require("mime")
    return mime.b64(data)
end

-- Test 15: RSA with small key
function rsa_encrypt_weak(data)
    -- VULNERABLE: RSA key too small
    local rsa = openssl.rsa.generate(512)  -- Should be 2048+
    return rsa:encrypt(data)
end

-- Test 16: SHA256 for HMAC without proper key
function weak_hmac(data)
    -- VULNERABLE: Weak/short HMAC key
    return crypto.hmac("sha256", data, "short")
end
