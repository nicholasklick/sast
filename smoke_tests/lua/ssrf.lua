-- Server-Side Request Forgery (SSRF) vulnerabilities in Lua

local http = require("socket.http")
local ltn12 = require("ltn12")

-- Test 1: HTTP request with user-controlled URL
function fetch_url(url)
    -- VULNERABLE: SSRF via user-controlled URL
    local response = {}
    http.request{
        url = url,
        sink = ltn12.sink.table(response)
    }
    return table.concat(response)
end

-- Test 2: OpenResty http client SSRF
function resty_http_fetch(url)
    local httpc = require("resty.http").new()
    -- VULNERABLE: User-controlled URL
    local res = httpc:request_uri(url)
    return res.body
end

-- Test 3: URL concatenation
function fetch_api(endpoint)
    -- VULNERABLE: Endpoint can be manipulated
    local url = "http://internal-api.local/" .. endpoint
    return http.request(url)
end

-- Test 4: ngx.location.capture SSRF
function proxy_request()
    local args = ngx.req.get_uri_args()
    local target = args.url
    -- VULNERABLE: Internal redirect to user URL
    local res = ngx.location.capture("/proxy", {
        vars = { target_url = target }
    })
    ngx.say(res.body)
end

-- Test 5: Socket connection to user host
function connect_to_host(host, port)
    local socket = require("socket")
    local tcp = socket.tcp()
    -- VULNERABLE: Connecting to arbitrary host
    tcp:connect(host, port)
    return tcp
end

-- Test 6: OpenResty socket SSRF
function resty_socket_connect()
    local args = ngx.req.get_uri_args()
    local host = args.host
    local port = args.port or 80
    local sock = ngx.socket.tcp()
    -- VULNERABLE: User-controlled socket connection
    sock:connect(host, tonumber(port))
end

-- Test 7: DNS rebinding potential
function fetch_with_host(host, path)
    -- VULNERABLE: Host header manipulation
    local url = "http://" .. host .. path
    return http.request(url)
end

-- Test 8: URL scheme manipulation
function fetch_resource(resource)
    -- VULNERABLE: Can use file:// or other schemes
    local url = resource
    return http.request(url)
end

-- Test 9: Redirect following
function fetch_with_redirect(url)
    local httpc = require("resty.http").new()
    -- VULNERABLE: May follow redirects to internal services
    local res = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = false
    })
    return res.body
end

-- Test 10: Webhook URL
function send_webhook(webhook_url, data)
    local httpc = require("resty.http").new()
    -- VULNERABLE: User-controlled webhook destination
    httpc:request_uri(webhook_url, {
        method = "POST",
        body = data
    })
end

-- Test 11: Image/file URL fetch
function fetch_image(image_url)
    -- VULNERABLE: Fetching from user URL
    local response = {}
    http.request{
        url = image_url,
        sink = ltn12.sink.table(response)
    }
    return table.concat(response)
end

-- Test 12: XML with external entity
function process_xml_url(xml_url)
    -- VULNERABLE: Fetching XML from user URL
    local content = fetch_url(xml_url)
    -- Parse XML...
    return content
end

-- Test 13: Database connection string
function connect_db(connection_string)
    -- VULNERABLE: User-controlled connection destination
    local pgmoon = require("pgmoon")
    local pg = pgmoon.new(parse_connection_string(connection_string))
    pg:connect()
    return pg
end

function parse_connection_string(str)
    -- Parse and return connection params
    return {host = "localhost", database = "test"}
end
