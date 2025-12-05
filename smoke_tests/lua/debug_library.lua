-- Debug Library Abuse vulnerabilities in Lua
-- The debug library can bypass security restrictions

-- Test 1: debug.getinfo to inspect functions
function inspect_function(func)
    -- VULNERABLE: Can reveal internal function details
    local info = debug.getinfo(func)
    return info
end

-- Test 2: debug.getlocal to read local variables
function read_locals(level)
    -- VULNERABLE: Can read arbitrary local variables
    local locals = {}
    local i = 1
    while true do
        local name, value = debug.getlocal(level, i)
        if not name then break end
        locals[name] = value
        i = i + 1
    end
    return locals
end

-- Test 3: debug.setlocal to modify local variables
function modify_local(level, index, value)
    -- VULNERABLE: Can modify arbitrary local variables
    debug.setlocal(level, index, value)
end

-- Test 4: debug.getupvalue to read upvalues
function read_upvalues(func)
    -- VULNERABLE: Can read closure upvalues
    local upvalues = {}
    local i = 1
    while true do
        local name, value = debug.getupvalue(func, i)
        if not name then break end
        upvalues[name] = value
        i = i + 1
    end
    return upvalues
end

-- Test 5: debug.setupvalue to modify upvalues
function modify_upvalue(func, index, value)
    -- VULNERABLE: Can modify closure upvalues
    debug.setupvalue(func, index, value)
end

-- Test 6: debug.sethook for code injection
function set_malicious_hook(func)
    -- VULNERABLE: Can intercept all function calls
    debug.sethook(func, "c")  -- Call hook
end

-- Test 7: debug.setmetatable to bypass restrictions
function bypass_metatable(obj, mt)
    -- VULNERABLE: Can set metatable on any object
    debug.setmetatable(obj, mt)
end

-- Test 8: debug.getregistry access
function access_registry()
    -- VULNERABLE: Access to internal registry
    return debug.getregistry()
end

-- Test 9: debug.getfenv to read function environment (Lua 5.1)
function get_function_env(func)
    -- VULNERABLE: Can read function environment
    return debug.getfenv(func)
end

-- Test 10: debug.setfenv to change function environment (Lua 5.1)
function set_function_env(func, env)
    -- VULNERABLE: Can change function environment
    debug.setfenv(func, env)
end

-- Test 11: User input to debug functions
function debug_from_input()
    local args = ngx.req.get_uri_args()
    local level = tonumber(args.level) or 2
    -- VULNERABLE: User controls debug level
    local info = debug.getinfo(level)
    ngx.say(serialize(info))
end

-- Test 12: Sandbox escape via debug
function escape_sandbox()
    -- VULNERABLE: Using debug to escape sandboxed environment
    local registry = debug.getregistry()
    local globals = registry._G or _G
    return globals
end

-- Test 13: Stack manipulation
function manipulate_stack(level)
    -- VULNERABLE: Can manipulate call stack
    local thread = coroutine.running()
    local info = debug.getinfo(thread, level, "Slnf")
    return info
end

-- Test 14: Traceback with sensitive info
function log_error(err)
    -- VULNERABLE: Traceback may reveal sensitive data
    local tb = debug.traceback(err)
    print(tb)
end

-- Helper function
function serialize(obj)
    if type(obj) == "table" then
        local s = "{"
        for k, v in pairs(obj) do
            s = s .. tostring(k) .. "=" .. tostring(v) .. ","
        end
        return s .. "}"
    end
    return tostring(obj)
end
