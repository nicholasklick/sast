-- Code Injection vulnerabilities in Lua
-- load, loadstring, loadfile, dofile patterns

-- Test 1: loadstring with user input
function eval_code(user_code)
    -- VULNERABLE: Arbitrary code execution
    local func = loadstring(user_code)
    if func then func() end
end

-- Test 2: load with user input (Lua 5.2+)
function load_code(code)
    -- VULNERABLE: load executes arbitrary code
    local func = load(code)
    if func then return func() end
end

-- Test 3: loadfile with user path
function load_script(path)
    -- VULNERABLE: Loading arbitrary Lua file
    local func = loadfile(path)
    if func then func() end
end

-- Test 4: dofile with user path
function do_script(script_path)
    -- VULNERABLE: Executing arbitrary Lua file
    dofile(script_path)
end

-- Test 5: require with user input
function dynamic_require(module_name)
    -- VULNERABLE: Loading arbitrary modules
    local module = require(module_name)
    return module
end

-- Test 6: package.loadlib
function load_c_library(path, func_name)
    -- VULNERABLE: Loading arbitrary C libraries
    local func = package.loadlib(path, func_name)
    if func then func() end
end

-- Test 7: setfenv manipulation (Lua 5.1)
function sandbox_escape(code)
    -- VULNERABLE: Can escape sandbox via setfenv
    local func = loadstring(code)
    setfenv(func, _G)
    func()
end

-- Test 8: Metatable manipulation
function metatable_attack(obj, mt_code)
    -- VULNERABLE: Arbitrary metatable
    local mt = loadstring("return " .. mt_code)()
    setmetatable(obj, mt)
end

-- Test 9: debug library abuse
function debug_injection(local_idx, value_code)
    -- VULNERABLE: Setting arbitrary local values
    local value = loadstring("return " .. value_code)()
    debug.setlocal(2, local_idx, value)
end

-- Test 10: rawset bypass
function rawset_injection(table, key, value_code)
    -- VULNERABLE: Bypassing metamethods
    local value = loadstring("return " .. value_code)()
    rawset(table, key, value)
end

-- Test 11: String to function conversion
function string_to_func(func_str)
    -- VULNERABLE: Converting user string to function
    return loadstring("return function() " .. func_str .. " end")()
end

-- Test 12: Template evaluation
function eval_template(template, vars)
    -- VULNERABLE: Template code injection
    local code = "return " .. string.gsub(template, "%$(%w+)", function(var)
        return "vars." .. var
    end)
    return loadstring(code)(vars)
end

-- Test 13: JSON with code execution
function parse_json_unsafe(json_str)
    -- VULNERABLE: Using loadstring for JSON parsing
    return loadstring("return " .. json_str)()
end

-- Test 14: OpenResty code injection
function openresty_eval()
    local args = ngx.req.get_uri_args()
    local code = args.code
    -- VULNERABLE: Request param to loadstring
    local func = loadstring(code)
    if func then
        local result = func()
        ngx.say(result)
    end
end

-- Test 15: Config file code execution
function load_config(config_path)
    -- VULNERABLE: Config files can contain arbitrary Lua
    local config = {}
    local chunk = loadfile(config_path)
    if chunk then
        setfenv(chunk, config)
        chunk()
    end
    return config
end
