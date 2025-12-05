-- Cross-Site Scripting (XSS) vulnerabilities in Lua
-- OpenResty/nginx-lua patterns

-- Test 1: Direct output of user input
function echo_input()
    local args = ngx.req.get_uri_args()
    local name = args.name
    -- VULNERABLE: Reflected XSS
    ngx.say("<h1>Hello, " .. name .. "!</h1>")
end

-- Test 2: ngx.print without escaping
function print_message()
    local args = ngx.req.get_uri_args()
    local msg = args.message
    -- VULNERABLE: XSS via ngx.print
    ngx.print("<div class='message'>" .. msg .. "</div>")
end

-- Test 3: Header injection
function set_custom_header()
    local args = ngx.req.get_uri_args()
    local value = args.header_value
    -- VULNERABLE: Header injection
    ngx.header["X-Custom"] = value
end

-- Test 4: Cookie value from user input
function set_cookie()
    local args = ngx.req.get_uri_args()
    local token = args.token
    -- VULNERABLE: Cookie injection
    ngx.header["Set-Cookie"] = "session=" .. token
end

-- Test 5: HTML template injection
function render_template(user_data)
    -- VULNERABLE: Template injection
    local html = [[
        <html>
        <body>
            <h1>Welcome, ]] .. user_data.name .. [[!</h1>
            <p>Email: ]] .. user_data.email .. [[</p>
        </body>
        </html>
    ]]
    ngx.say(html)
end

-- Test 6: JSON response with user data
function json_response()
    local args = ngx.req.get_uri_args()
    local callback = args.callback
    local data = '{"status": "ok"}'
    -- VULNERABLE: JSONP callback injection
    ngx.say(callback .. "(" .. data .. ")")
end

-- Test 7: Error message with user input
function show_error()
    local args = ngx.req.get_uri_args()
    local error_msg = args.error
    -- VULNERABLE: Error message XSS
    ngx.say("<div class='error'>Error: " .. error_msg .. "</div>")
end

-- Test 8: URL in redirect
function redirect_user()
    local args = ngx.req.get_uri_args()
    local next_url = args.next
    -- VULNERABLE: Open redirect and potential XSS
    ngx.redirect(next_url)
end

-- Test 9: Building HTML table from data
function render_table(rows)
    ngx.say("<table>")
    for _, row in ipairs(rows) do
        -- VULNERABLE: XSS in table cells
        ngx.say("<tr><td>" .. row.name .. "</td><td>" .. row.value .. "</td></tr>")
    end
    ngx.say("</table>")
end

-- Test 10: JavaScript variable injection
function inject_js_var()
    local args = ngx.req.get_uri_args()
    local user_id = args.user_id
    -- VULNERABLE: JavaScript injection
    ngx.say("<script>var userId = '" .. user_id .. "';</script>")
end

-- Test 11: Attribute injection
function render_link()
    local args = ngx.req.get_uri_args()
    local url = args.url
    local text = args.text
    -- VULNERABLE: Attribute injection
    ngx.say('<a href="' .. url .. '">' .. text .. '</a>')
end

-- Test 12: Style injection
function custom_style()
    local args = ngx.req.get_uri_args()
    local color = args.color
    -- VULNERABLE: CSS injection
    ngx.say('<div style="color: ' .. color .. '">Styled text</div>')
end

-- Test 13: Event handler injection
function render_button()
    local args = ngx.req.get_uri_args()
    local action = args.action
    -- VULNERABLE: Event handler XSS
    ngx.say('<button onclick="' .. action .. '">Click me</button>')
end
