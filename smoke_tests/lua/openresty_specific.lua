-- OpenResty/nginx-lua Specific vulnerabilities

-- Test 1: Shared dictionary race condition
function increment_counter(key)
    local shared = ngx.shared.counters
    local count = shared:get(key) or 0
    -- VULNERABLE: Non-atomic increment
    shared:set(key, count + 1)
end

-- Test 2: ngx.var injection
function set_variable()
    local args = ngx.req.get_uri_args()
    local value = args.value
    -- VULNERABLE: Setting nginx variable from user input
    ngx.var.user_value = value
end

-- Test 3: SSL verification disabled
function insecure_https_request(url)
    local httpc = require("resty.http").new()
    -- VULNERABLE: SSL verification disabled
    local res = httpc:request_uri(url, {
        ssl_verify = false
    })
    return res
end

-- Test 4: Cosocket timeout issues
function long_running_request(url)
    local httpc = require("resty.http").new()
    -- VULNERABLE: No timeout set (can hang indefinitely)
    httpc:set_timeout(0)  -- No timeout
    return httpc:request_uri(url)
end

-- Test 5: Body data not read
function process_post_data()
    -- VULNERABLE: Body may not be read in some phases
    local body = ngx.req.get_body_data()
    -- Body could be nil if not read
    ngx.say(body)
end

-- Test 6: Exit without return
function auth_check()
    local token = ngx.req.get_headers()["Authorization"]
    if not token then
        ngx.status = 401
        ngx.exit(401)
        -- VULNERABLE: Code continues after exit without return
    end
    -- This code may still execute
    process_authenticated_request()
end

-- Test 7: Content-Type header injection
function set_content_type()
    local args = ngx.req.get_uri_args()
    local content_type = args.type
    -- VULNERABLE: User-controlled Content-Type
    ngx.header["Content-Type"] = content_type
end

-- Test 8: Phase limitation bypass attempt
function access_phase_operation()
    -- VULNERABLE: Some operations not allowed in certain phases
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    -- May fail in access phase
end

-- Test 9: Subrequest with user URI
function make_subrequest()
    local args = ngx.req.get_uri_args()
    local uri = args.uri
    -- VULNERABLE: User-controlled subrequest URI
    local res = ngx.location.capture(uri)
    ngx.say(res.body)
end

-- Test 10: Shared memory data exposure
function dump_shared_dict()
    local shared = ngx.shared.my_cache
    -- VULNERABLE: Exposing all cached data
    local keys = shared:get_keys(0)
    for _, key in ipairs(keys) do
        ngx.say(key .. " = " .. tostring(shared:get(key)))
    end
end

-- Test 11: Upstream selection manipulation
function select_upstream()
    local args = ngx.req.get_uri_args()
    local backend = args.backend
    -- VULNERABLE: User-controlled upstream
    ngx.var.backend = backend
end

-- Test 12: Log phase data exposure
function log_request_data()
    -- VULNERABLE: Logging sensitive data in log phase
    local headers = ngx.req.get_headers()
    ngx.log(ngx.INFO, "Authorization: " .. (headers["Authorization"] or "none"))
end

-- Test 13: Timer with user code
function schedule_task()
    local args = ngx.req.get_uri_args()
    local code = args.code
    -- VULNERABLE: User code in timer callback
    ngx.timer.at(0, function()
        loadstring(code)()
    end)
    ngx.say("Scheduled")
end

-- Test 14: Redis injection via resty.redis
function redis_command()
    local args = ngx.req.get_uri_args()
    local key = args.key
    local redis = require("resty.redis"):new()
    redis:connect("127.0.0.1", 6379)
    -- VULNERABLE: User-controlled key
    local res = redis:get(key)
    ngx.say(res)
end

-- Test 15: Response body substitution
function filter_response()
    local args = ngx.req.get_uri_args()
    local pattern = args.pattern
    local replacement = args.replace
    -- VULNERABLE: User-controlled pattern/replacement
    ngx.arg[1] = ngx.re.gsub(ngx.arg[1], pattern, replacement)
end

-- Helper function (stub)
function process_authenticated_request()
    ngx.say("Authenticated")
end
