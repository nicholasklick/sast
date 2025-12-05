-- Insecure Deserialization vulnerabilities in Lua

-- Test 1: loadstring for data parsing
function parse_data(data_str)
    -- VULNERABLE: Executing data as code
    return loadstring("return " .. data_str)()
end

-- Test 2: Unsafe JSON parsing via loadstring
function parse_json_unsafe(json_str)
    -- VULNERABLE: Using loadstring for JSON
    return loadstring("return " .. json_str)()
end

-- Test 3: load() for deserialization
function deserialize(serialized)
    -- VULNERABLE: load() executes code
    return load("return " .. serialized)()
end

-- Test 4: Lua table serialization/deserialization
function deserialize_table(str)
    -- VULNERABLE: Executing serialized Lua table
    local func = loadstring("return " .. str)
    if func then
        return func()
    end
end

-- Test 5: File-based deserialization
function load_saved_data(filepath)
    local file = io.open(filepath, "r")
    local content = file:read("*a")
    file:close()
    -- VULNERABLE: Loading and executing file content
    return loadstring("return " .. content)()
end

-- Test 6: Network data deserialization
function receive_and_deserialize(socket)
    local data = socket:receive("*a")
    -- VULNERABLE: Deserializing network data
    return loadstring("return " .. data)()
end

-- Test 7: Cookie deserialization
function deserialize_cookie()
    local args = ngx.req.get_uri_args()
    local cookie_data = args.session
    -- VULNERABLE: Deserializing cookie data
    return loadstring("return " .. ngx.decode_base64(cookie_data))()
end

-- Test 8: Pickle-like serialization
function unpickle(serialized_str)
    -- VULNERABLE: Custom serialization with code execution
    local func = loadstring([[
        local data = {}
        ]] .. serialized_str .. [[
        return data
    ]])
    return func()
end

-- Test 9: Message queue deserialization
function process_queue_message(message)
    -- VULNERABLE: Deserializing queue message
    local payload = loadstring("return " .. message.body)()
    return payload
end

-- Test 10: Redis value deserialization
function get_cached_object(redis, key)
    local serialized = redis:get(key)
    -- VULNERABLE: Deserializing cached data
    return loadstring("return " .. serialized)()
end

-- Test 11: YAML-like parsing via loadstring
function parse_config(config_str)
    -- VULNERABLE: Config parsing with code execution
    local config = {}
    local chunk = loadstring("return function(cfg) " .. config_str .. " end")
    if chunk then
        chunk()(config)
    end
    return config
end

-- Test 12: Database blob deserialization
function load_from_db(row)
    local serialized = row.data
    -- VULNERABLE: Deserializing database blob
    return loadstring("return " .. serialized)()
end

-- Test 13: WebSocket message deserialization
function handle_ws_message(message)
    -- VULNERABLE: Deserializing WebSocket data
    local data = loadstring("return " .. message)()
    process_data(data)
end

-- Test 14: multipart form deserialization
function process_upload()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    -- VULNERABLE: Deserializing uploaded content
    return loadstring("return " .. body)()
end

function process_data(data)
    -- stub
end
