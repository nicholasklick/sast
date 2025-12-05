-- Metatable Abuse vulnerabilities in Lua
-- Metatables can be used to override behavior and bypass security

-- Test 1: setmetatable with user input
function set_user_metatable(obj, mt_string)
    -- VULNERABLE: User-controlled metatable
    local mt = loadstring("return " .. mt_string)()
    setmetatable(obj, mt)
end

-- Test 2: __index metamethod injection
function create_proxy_table(target, index_func_code)
    -- VULNERABLE: User-controlled __index
    local func = loadstring("return " .. index_func_code)()
    local mt = { __index = func }
    return setmetatable({}, mt)
end

-- Test 3: __newindex for write interception
function intercept_writes(obj, newindex_code)
    -- VULNERABLE: User-controlled __newindex
    local func = loadstring("return " .. newindex_code)()
    local mt = { __newindex = func }
    setmetatable(obj, mt)
end

-- Test 4: __call metamethod code injection
function make_callable(obj, call_code)
    -- VULNERABLE: User-controlled __call
    local func = loadstring("return " .. call_code)()
    local mt = { __call = func }
    return setmetatable(obj, mt)
end

-- Test 5: __tostring for output manipulation
function custom_tostring(obj, tostring_code)
    -- VULNERABLE: User-controlled __tostring
    local func = loadstring("return " .. tostring_code)()
    local mt = { __tostring = func }
    setmetatable(obj, mt)
end

-- Test 6: __gc finalizer injection
function set_finalizer(obj, gc_code)
    -- VULNERABLE: User-controlled garbage collector hook
    local func = loadstring("return " .. gc_code)()
    local proxy = newproxy(true)
    getmetatable(proxy).__gc = func
    obj._finalizer = proxy
end

-- Test 7: Arithmetic metamethod injection
function math_injection(obj, add_code)
    -- VULNERABLE: User-controlled __add
    local func = loadstring("return " .. add_code)()
    local mt = { __add = func }
    setmetatable(obj, mt)
end

-- Test 8: Comparison metamethod injection
function compare_injection(obj, eq_code)
    -- VULNERABLE: User-controlled __eq
    local func = loadstring("return " .. eq_code)()
    local mt = { __eq = func }
    setmetatable(obj, mt)
end

-- Test 9: __len metamethod manipulation
function length_manipulation(obj, len_code)
    -- VULNERABLE: User-controlled __len
    local func = loadstring("return " .. len_code)()
    local mt = { __len = func }
    setmetatable(obj, mt)
end

-- Test 10: rawget/rawset bypass detection
function bypass_metamethods(obj, key)
    -- Using rawget to bypass __index (security mechanism bypass)
    return rawget(obj, key)
end

-- Test 11: Metatable inheritance attack
function create_poisoned_parent(poison_code)
    -- VULNERABLE: Parent metatable with malicious code
    local func = loadstring("return " .. poison_code)()
    local parent_mt = { __index = func }
    local child = setmetatable({}, setmetatable({}, parent_mt))
    return child
end

-- Test 12: Protected metatable bypass
function access_protected_metatable(obj)
    -- Attempting to access protected metatable
    local mt = getmetatable(obj)
    if type(mt) == "string" then
        -- Metatable is protected, but debug.getmetatable can bypass
        return debug.getmetatable(obj)
    end
    return mt
end

-- Test 13: Global table metatable
function poison_global_table(index_code)
    -- VULNERABLE: Setting metatable on _G
    local func = loadstring("return " .. index_code)()
    setmetatable(_G, { __index = func })
end

-- Test 14: String metatable modification
function modify_string_mt(method_name, method_code)
    -- VULNERABLE: Adding methods to all strings
    local func = loadstring("return " .. method_code)()
    local string_mt = getmetatable("")
    string_mt.__index[method_name] = func
end
