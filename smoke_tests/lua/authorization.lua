-- Authorization vulnerabilities in Lua

-- Test 1: Missing authorization check
function delete_user(user_id)
    -- VULNERABLE: No authorization check
    db:execute("DELETE FROM users WHERE id = " .. user_id)
end

-- Test 2: IDOR (Insecure Direct Object Reference)
function get_user_data(user_id)
    -- VULNERABLE: No ownership verification
    return db:query("SELECT * FROM users WHERE id = " .. user_id)
end

-- Test 3: Horizontal privilege escalation
function update_profile(user_id, data)
    -- VULNERABLE: Can update any user's profile
    db:execute("UPDATE users SET name = '" .. data.name .. "' WHERE id = " .. user_id)
end

-- Test 4: Vertical privilege escalation
function set_user_role(user_id, role)
    -- VULNERABLE: No admin check
    db:execute("UPDATE users SET role = '" .. role .. "' WHERE id = " .. user_id)
end

-- Test 5: Client-side authorization
function admin_panel(request)
    -- VULNERABLE: Trusting client-side flag
    if request.params.is_admin == "true" then
        return render_admin_panel()
    end
    return "Access Denied"
end

-- Test 6: Parameter tampering
function access_resource(request)
    -- VULNERABLE: user_id from request, not session
    local user_id = request.params.user_id
    return get_resource_for_user(user_id)
end

-- Test 7: Missing function-level access control
function admin_action(action)
    -- VULNERABLE: No role check
    if action == "delete_all" then
        db:execute("DELETE FROM users")
    elseif action == "export" then
        export_all_data()
    end
end

-- Test 8: Path-based authorization bypass
function access_file(path)
    -- VULNERABLE: No path authorization
    local file = io.open("/uploads/" .. path, "r")
    return file:read("*a")
end

-- Test 9: Broken access control in API
function handle_api_request(endpoint, request)
    -- VULNERABLE: No authorization
    if endpoint == "/users" then
        return get_all_users()
    elseif endpoint == "/admin/settings" then
        return get_admin_settings()
    end
end

-- Test 10: Mass assignment with role
function update_user(user_id, params)
    local user = get_user(user_id)
    -- VULNERABLE: Can set is_admin via params
    for key, value in pairs(params) do
        user[key] = value
    end
    save_user(user)
end

-- Test 11: Debug backdoor
function validate_token(token)
    -- VULNERABLE: Debug backdoor
    if token == "debug" then
        return true
    end
    return verify_jwt(token)
end

-- Test 12: Role check bypass
function require_admin(request)
    local role = request.cookies.role
    -- VULNERABLE: Role from cookie (client-controlled)
    return role == "admin"
end

-- Test 13: ngx.var authorization bypass
function openresty_auth()
    -- VULNERABLE: Trusting request headers for auth
    local user_role = ngx.req.get_headers()["X-User-Role"]
    if user_role == "admin" then
        return true
    end
    return false
end

-- Test 14: Race condition in authorization
function withdraw_funds(user_id, amount)
    local balance = get_balance(user_id)
    -- VULNERABLE: TOCTOU race condition
    if balance >= amount then
        -- Time gap allows race condition
        update_balance(user_id, balance - amount)
        return true
    end
    return false
end

-- Helper functions (stubs)
db = {
    execute = function(query) end,
    query = function(query) return {} end
}

function render_admin_panel() return "Admin Panel" end
function get_resource_for_user(id) return {} end
function export_all_data() end
function get_all_users() return {} end
function get_admin_settings() return {} end
function get_user(id) return {} end
function save_user(user) end
function verify_jwt(token) return false end
function get_balance(id) return 0 end
function update_balance(id, amount) end
