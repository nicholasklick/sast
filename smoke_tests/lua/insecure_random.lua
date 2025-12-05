-- Insecure Random Number Generation in Lua

-- Test 1: math.random without proper seed
function generate_token_weak()
    -- VULNERABLE: Default seed is predictable
    local token = ""
    for i = 1, 32 do
        token = token .. string.char(math.random(65, 90))
    end
    return token
end

-- Test 2: Time-based seed
function generate_session_id()
    -- VULNERABLE: Time-based seed is predictable
    math.randomseed(os.time())
    return math.random(1000000, 9999999)
end

-- Test 3: Weak password generation
function generate_password(length)
    math.randomseed(os.time())
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local password = ""
    -- VULNERABLE: Predictable random
    for i = 1, length do
        local idx = math.random(1, #chars)
        password = password .. chars:sub(idx, idx)
    end
    return password
end

-- Test 4: UUID generation
function generate_uuid()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable UUID
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return template:gsub("[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end)
end

-- Test 5: OTP generation
function generate_otp()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable OTP
    return string.format("%06d", math.random(0, 999999))
end

-- Test 6: API key generation
function generate_api_key()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable API key
    local key = ""
    for i = 1, 32 do
        key = key .. string.format("%02x", math.random(0, 255))
    end
    return key
end

-- Test 7: CSRF token generation
function generate_csrf_token()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable CSRF token
    return tostring(math.random(10000000, 99999999))
end

-- Test 8: Nonce generation
function generate_nonce()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable nonce
    local nonce = ""
    for i = 1, 16 do
        nonce = nonce .. string.format("%02x", math.random(0, 255))
    end
    return nonce
end

-- Test 9: Encryption IV generation
function generate_iv()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable IV
    local iv = ""
    for i = 1, 16 do
        iv = iv .. string.char(math.random(0, 255))
    end
    return iv
end

-- Test 10: Salt generation
function generate_salt()
    math.randomseed(os.time())
    -- VULNERABLE: Predictable salt
    local salt = ""
    for i = 1, 16 do
        salt = salt .. string.format("%02x", math.random(0, 255))
    end
    return salt
end

-- Test 11: Shuffle with weak random
function shuffle_array(arr)
    math.randomseed(os.time())
    -- VULNERABLE: Predictable shuffle
    for i = #arr, 2, -1 do
        local j = math.random(i)
        arr[i], arr[j] = arr[j], arr[i]
    end
    return arr
end

-- Test 12: Random selection
function select_random_winner(participants)
    math.randomseed(os.time())
    -- VULNERABLE: Predictable winner selection
    local idx = math.random(1, #participants)
    return participants[idx]
end

-- Test 13: Process ID as seed (slightly better but still weak)
function generate_token_pid_seed()
    -- VULNERABLE: PID + time still predictable
    math.randomseed(os.time() + (os.getenv("PID") or 0))
    return math.random(1000000000, 9999999999)
end
