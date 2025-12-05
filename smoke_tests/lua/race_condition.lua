-- Race Condition vulnerabilities in Lua

-- Test 1: TOCTOU in file operations
function safe_delete(path)
    -- VULNERABLE: TOCTOU race condition
    if file_exists(path) then
        -- Time gap between check and use
        os.remove(path)
    end
end

-- Test 2: Balance check race condition
function withdraw(user_id, amount)
    local balance = get_balance(user_id)
    -- VULNERABLE: Balance can change between check and update
    if balance >= amount then
        update_balance(user_id, balance - amount)
        return true
    end
    return false
end

-- Test 3: Inventory race condition
function purchase_item(user_id, item_id, quantity)
    local stock = get_stock(item_id)
    -- VULNERABLE: Stock can change
    if stock >= quantity then
        decrease_stock(item_id, quantity)
        add_to_cart(user_id, item_id, quantity)
    end
end

-- Test 4: Coupon usage race
function apply_coupon(coupon_code, order_id)
    local coupon = get_coupon(coupon_code)
    -- VULNERABLE: Coupon can be used multiple times
    if coupon and coupon.uses_remaining > 0 then
        apply_discount(order_id, coupon.discount)
        decrement_coupon_uses(coupon_code)
    end
end

-- Test 5: Session race condition
function login(username, password, session)
    if verify_credentials(username, password) then
        -- VULNERABLE: Session manipulation during login
        session.user = username
        session.logged_in = true
        session.login_time = os.time()
    end
end

-- Test 6: File creation race
function create_temp_file(data)
    local path = "/tmp/app_" .. os.time()
    -- VULNERABLE: File can be created by attacker
    if not file_exists(path) then
        local file = io.open(path, "w")
        file:write(data)
        file:close()
    end
end

-- Test 7: Lock-free counter
local request_count = 0

function handle_request()
    -- VULNERABLE: Non-atomic increment
    request_count = request_count + 1
    -- Process request...
end

-- Test 8: Rate limiting race
function check_rate_limit(user_id)
    local count = get_request_count(user_id)
    -- VULNERABLE: Race in rate limiting
    if count < 100 then
        increment_request_count(user_id)
        return true
    end
    return false
end

-- Test 9: Double spending
function process_payment(user_id, amount)
    local pending = get_pending_transactions(user_id)
    -- VULNERABLE: Can submit multiple transactions
    if not pending then
        set_pending(user_id, true)
        process_transaction(user_id, amount)
        set_pending(user_id, false)
    end
end

-- Test 10: Sequence number race
local sequence = 0

function get_next_sequence()
    -- VULNERABLE: Non-atomic operation
    sequence = sequence + 1
    return sequence
end

-- Test 11: Cache race condition
function get_cached_data(key)
    local data = cache:get(key)
    -- VULNERABLE: Cache can be modified during processing
    if not data then
        data = fetch_from_db(key)
        cache:set(key, data)
    end
    return data
end

-- Test 12: User registration race
function register_user(username, password)
    -- VULNERABLE: Username can be taken between check and insert
    if not user_exists(username) then
        create_user(username, password)
        return true
    end
    return false
end

-- Test 13: Shared state in coroutines
local shared_data = {}

function coroutine_handler(key, value)
    -- VULNERABLE: Shared state between coroutines
    shared_data[key] = value
    coroutine.yield()
    -- Value may have changed
    return shared_data[key]
end

-- Helper functions (stubs)
function file_exists(path) return false end
function get_balance(id) return 100 end
function update_balance(id, amount) end
function get_stock(id) return 10 end
function decrease_stock(id, qty) end
function add_to_cart(uid, iid, qty) end
function get_coupon(code) return {uses_remaining = 1, discount = 10} end
function apply_discount(order, discount) end
function decrement_coupon_uses(code) end
function verify_credentials(u, p) return true end
function get_request_count(id) return 0 end
function increment_request_count(id) end
function get_pending_transactions(id) return nil end
function set_pending(id, val) end
function process_transaction(id, amt) end
function fetch_from_db(key) return {} end
function user_exists(username) return false end
function create_user(username, password) end
cache = { get = function(k) return nil end, set = function(k, v) end }
