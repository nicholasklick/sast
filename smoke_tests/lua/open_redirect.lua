-- Open Redirect vulnerabilities in Lua (OpenResty)

-- Test 1: Direct redirect from parameter
function redirect_to_url()
    local args = ngx.req.get_uri_args()
    local url = args.url
    -- VULNERABLE: Open redirect
    ngx.redirect(url)
end

-- Test 2: Redirect with next parameter
function login_redirect()
    local args = ngx.req.get_uri_args()
    local next_url = args.next or "/"
    -- Perform login...
    -- VULNERABLE: Redirect to user-controlled URL
    ngx.redirect(next_url)
end

-- Test 3: Header-based redirect
function header_redirect()
    local args = ngx.req.get_uri_args()
    local location = args.redirect_to
    -- VULNERABLE: Location header injection
    ngx.header["Location"] = location
    ngx.exit(302)
end

-- Test 4: Callback URL redirect
function oauth_callback()
    local args = ngx.req.get_uri_args()
    local callback = args.callback
    -- After OAuth processing...
    -- VULNERABLE: Callback URL from user
    ngx.redirect(callback)
end

-- Test 5: Return URL after action
function process_and_redirect()
    local args = ngx.req.get_uri_args()
    local return_url = args.return_to
    -- Process action...
    -- VULNERABLE: Return URL from user
    ngx.redirect(return_url)
end

-- Test 6: Meta refresh redirect
function meta_redirect()
    local args = ngx.req.get_uri_args()
    local target = args.target
    -- VULNERABLE: Meta refresh to user URL
    ngx.say('<meta http-equiv="refresh" content="0;url=' .. target .. '">')
end

-- Test 7: JavaScript redirect
function js_redirect()
    local args = ngx.req.get_uri_args()
    local dest = args.dest
    -- VULNERABLE: JavaScript redirect
    ngx.say('<script>window.location="' .. dest .. '";</script>')
end

-- Test 8: Partial URL validation bypass
function validated_redirect()
    local args = ngx.req.get_uri_args()
    local url = args.url
    -- VULNERABLE: Insufficient validation (can bypass with //evil.com)
    if url:sub(1, 1) == "/" then
        ngx.redirect(url)
    end
end

-- Test 9: Protocol-relative redirect
function protocol_relative()
    local args = ngx.req.get_uri_args()
    local site = args.site
    -- VULNERABLE: Protocol-relative URL
    ngx.redirect("//" .. site .. "/page")
end

-- Test 10: Redirect with referer
function referer_redirect()
    local referer = ngx.req.get_headers()["Referer"]
    -- VULNERABLE: Redirect to referer (can be spoofed)
    if referer then
        ngx.redirect(referer)
    end
end

-- Test 11: URL concatenation redirect
function concat_redirect()
    local args = ngx.req.get_uri_args()
    local path = args.path
    -- VULNERABLE: Path could be //evil.com
    local url = "https://example.com" .. path
    ngx.redirect(url)
end

-- Test 12: Form action redirect
function render_form()
    local args = ngx.req.get_uri_args()
    local action = args.action
    -- VULNERABLE: Form action from user
    ngx.say('<form action="' .. action .. '" method="POST">')
    ngx.say('<input type="submit" value="Submit">')
    ngx.say('</form>')
end

-- Test 13: Frame redirect
function frame_redirect()
    local args = ngx.req.get_uri_args()
    local frame_url = args.frame
    -- VULNERABLE: iframe src from user
    ngx.say('<iframe src="' .. frame_url .. '"></iframe>')
end
