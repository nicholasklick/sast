-- Information Disclosure vulnerabilities in Lua

-- Test 1: Detailed error messages
function process_request(data)
    local status, err = pcall(function()
        parse_data(data)
    end)
    if not status then
        -- VULNERABLE: Detailed error to user
        ngx.say("Error: " .. tostring(err))
    end
end

-- Test 2: Stack trace exposure
function handle_error(err)
    -- VULNERABLE: Stack trace in response
    ngx.say("<pre>")
    ngx.say("Error: " .. err)
    ngx.say(debug.traceback())
    ngx.say("</pre>")
end

-- Test 3: Server version disclosure
function server_info()
    -- VULNERABLE: Version information exposed
    ngx.say("Server: OpenResty/" .. ngx.config.nginx_version)
    ngx.say("Lua: " .. _VERSION)
end

-- Test 4: Database error details
function execute_query(sql)
    local status, result = pcall(function()
        return db:query(sql)
    end)
    if not status then
        -- VULNERABLE: SQL error exposed
        ngx.say("Database error: " .. tostring(result))
    end
end

-- Test 5: File path disclosure
function read_config()
    local path = "/etc/app/config.lua"
    local file = io.open(path, "r")
    if not file then
        -- VULNERABLE: Full path in error
        error("Config not found at: " .. path)
    end
end

-- Test 6: Debug information exposure
function debug_endpoint()
    -- VULNERABLE: Debug info exposed
    local info = {
        lua_version = _VERSION,
        memory = collectgarbage("count"),
        uptime = ngx.now() - ngx.req.start_time(),
        worker_pid = ngx.worker.pid(),
        config = ngx.config
    }
    ngx.say(serialize(info))
end

-- Test 7: Environment variable exposure
function show_environment()
    -- VULNERABLE: All env vars exposed
    local env_vars = {}
    for key, value in pairs(os.getenv) do
        env_vars[key] = value
    end
    ngx.say(serialize(env_vars))
end

-- Test 8: User enumeration
function check_user(email)
    local user = find_user_by_email(email)
    if user then
        -- VULNERABLE: Reveals user exists
        ngx.say("User exists, check your password")
    else
        ngx.say("No user found with this email")
    end
end

-- Test 9: Timing-based information leak
function verify_credentials(username, password)
    local user = find_user(username)
    if not user then
        return false  -- VULNERABLE: Fast return reveals no user
    end
    return verify_password(password, user.password_hash)
end

-- Test 10: Internal IP disclosure
function network_info()
    -- VULNERABLE: Internal network info
    local socket = require("socket")
    local ip = socket.dns.toip(socket.dns.gethostname())
    ngx.say("Internal IP: " .. ip)
end

-- Test 11: Directory listing
function list_directory(path)
    local handle = io.popen("ls -la " .. path)
    local result = handle:read("*a")
    -- VULNERABLE: Directory listing exposed
    ngx.say("<pre>" .. result .. "</pre>")
end

-- Test 12: Verbose response headers
function set_verbose_headers()
    -- VULNERABLE: Internal details in headers
    ngx.header["X-Server-Node"] = "node-02.internal"
    ngx.header["X-DB-Replica"] = "db-replica-3"
    ngx.header["X-Cache-Status"] = "HIT from cache-01"
end

-- Test 13: Exception details
function parse_json(data)
    local cjson = require("cjson")
    local status, result = pcall(cjson.decode, data)
    if not status then
        -- VULNERABLE: JSON parse error details
        ngx.status = 400
        ngx.say('{"error": "JSON parse failed: ' .. result .. '"}')
    end
end

-- Helper functions (stubs)
function parse_data(data) end
function find_user_by_email(email) return nil end
function find_user(username) return nil end
function verify_password(password, hash) return false end
function serialize(obj) return tostring(obj) end
db = { query = function(sql) return {} end }
