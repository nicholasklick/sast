-- XML External Entity (XXE) vulnerabilities in Lua

local lxp = require("lxp")

-- Test 1: Basic XXE with LuaExpat
function parse_xml_unsafe(xml_string)
    -- VULNERABLE: External entities enabled by default
    local parser = lxp.new({})
    local result = {}
    parser:parse(xml_string)
    return result
end

-- Test 2: XML from user input
function process_user_xml()
    local args = ngx.req.get_uri_args()
    local xml_data = args.xml
    -- VULNERABLE: Parsing untrusted XML
    local parser = lxp.new({})
    parser:parse(xml_data)
end

-- Test 3: XML from file
function parse_xml_file(filepath)
    local file = io.open(filepath, "r")
    local xml_content = file:read("*a")
    file:close()
    -- VULNERABLE: Parsing XML from untrusted file
    local parser = lxp.new({})
    parser:parse(xml_content)
end

-- Test 4: XML from HTTP request body
function handle_xml_post()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    -- VULNERABLE: Parsing POST body as XML
    local parser = lxp.new({})
    parser:parse(body)
end

-- Test 5: SOAP message parsing
function process_soap_request(soap_xml)
    -- VULNERABLE: SOAP with XXE
    local parser = lxp.new({
        StartElement = function(parser, name, attrs)
            -- Process SOAP elements
        end
    })
    parser:parse(soap_xml)
end

-- Test 6: XML-RPC parsing
function handle_xmlrpc(request_xml)
    -- VULNERABLE: XML-RPC with XXE
    local parser = lxp.new({})
    parser:parse(request_xml)
end

-- Test 7: SVG parsing (XML-based)
function process_svg(svg_content)
    -- VULNERABLE: SVG files can contain XXE
    local parser = lxp.new({})
    parser:parse(svg_content)
end

-- Test 8: RSS/Atom feed parsing
function parse_feed(feed_url)
    local http = require("socket.http")
    local body = http.request(feed_url)
    -- VULNERABLE: Parsing untrusted feed
    local parser = lxp.new({})
    parser:parse(body)
end

-- Test 9: XPath evaluation with XXE
function xpath_query(xml_doc, xpath_expr)
    -- VULNERABLE: XML document may contain XXE
    local parser = lxp.new({})
    parser:parse(xml_doc)
    -- Evaluate XPath...
end

-- Test 10: XML configuration loading
function load_xml_config(config_path)
    local file = io.open(config_path, "r")
    local xml = file:read("*a")
    file:close()
    -- VULNERABLE: Config file XXE
    local parser = lxp.new({})
    parser:parse(xml)
end

-- Test 11: XSLT transformation
function apply_xslt(xml_doc, xslt_doc)
    -- VULNERABLE: Both XML and XSLT can contain XXE
    local parser = lxp.new({})
    parser:parse(xml_doc)
    -- Apply transformation...
end

-- Test 12: XML signature verification
function verify_xml_signature(signed_xml)
    -- VULNERABLE: XML signature with XXE
    local parser = lxp.new({})
    parser:parse(signed_xml)
end

-- Test 13: Webhook XML payload
function handle_webhook()
    ngx.req.read_body()
    local payload = ngx.req.get_body_data()
    local content_type = ngx.req.get_headers()["Content-Type"]

    if content_type and content_type:find("xml") then
        -- VULNERABLE: XML webhook payload
        local parser = lxp.new({})
        parser:parse(payload)
    end
end
