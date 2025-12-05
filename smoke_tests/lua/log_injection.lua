-- Log Injection vulnerabilities in Lua

-- Test 1: Basic log injection with print
function log_user_action(username, action)
    -- VULNERABLE: User input in log
    print("[INFO] User " .. username .. " performed action: " .. action)
end

-- Test 2: io.write log injection
function write_log(message)
    local log_file = io.open("/var/log/app.log", "a")
    -- VULNERABLE: Unsanitized message
    log_file:write(os.date() .. " - " .. message .. "\n")
    log_file:close()
end

-- Test 3: ngx.log injection
function openresty_log()
    local args = ngx.req.get_uri_args()
    local user_id = args.user_id
    -- VULNERABLE: Request param in log
    ngx.log(ngx.ERR, "Processing request for user: " .. user_id)
end

-- Test 4: Multi-line log injection
function log_request_details(request)
    -- VULNERABLE: Newlines can forge log entries
    print("[REQUEST] Path: " .. request.path .. " User: " .. request.user)
end

-- Test 5: Log sensitive data
function log_login_attempt(username, password)
    -- VULNERABLE: Logging password
    print("[AUTH] Login attempt - User: " .. username .. " Password: " .. password)
end

-- Test 6: Error logging with user input
function log_error(error_msg, user_input)
    -- VULNERABLE: User input in error log
    io.stderr:write("ERROR: " .. error_msg .. " - Input: " .. user_input .. "\n")
end

-- Test 7: Debug logging sensitive data
function debug_log(data)
    -- VULNERABLE: Logging entire data structure
    print("[DEBUG] Data: " .. serialize(data))
end

-- Test 8: Access log manipulation
function log_access()
    local args = ngx.req.get_uri_args()
    local client_ip = args.forwarded_ip or ngx.var.remote_addr
    -- VULNERABLE: Spoofable IP in log
    ngx.log(ngx.INFO, "Access from: " .. client_ip)
end

-- Test 9: Format string in log
function formatted_log(template, ...)
    local args = {...}
    -- VULNERABLE: Template could contain malicious format
    print(string.format(template, unpack(args)))
end

-- Test 10: Log forging via headers
function log_request_headers()
    local headers = ngx.req.get_headers()
    local user_agent = headers["User-Agent"]
    -- VULNERABLE: Headers can contain newlines
    ngx.log(ngx.INFO, "User-Agent: " .. (user_agent or "unknown"))
end

-- Test 11: Audit log injection
function audit_log(user, action, resource)
    local log_entry = string.format(
        "[AUDIT] User=%s Action=%s Resource=%s",
        user, action, resource
    )
    -- VULNERABLE: All fields from user input
    print(log_entry)
end

-- Test 12: Exception logging
function log_exception(err, context)
    -- VULNERABLE: Context may contain sensitive data
    print("[EXCEPTION] " .. tostring(err) .. " Context: " .. serialize(context))
end

-- Test 13: SQL query logging
function log_query(query, params)
    -- VULNERABLE: Logging SQL with params
    print("[SQL] " .. query .. " Params: " .. table.concat(params, ", "))
end

-- Helper function (stub)
function serialize(obj)
    if type(obj) == "table" then
        local s = "{ "
        for k, v in pairs(obj) do
            s = s .. tostring(k) .. "=" .. tostring(v) .. " "
        end
        return s .. "}"
    end
    return tostring(obj)
end
