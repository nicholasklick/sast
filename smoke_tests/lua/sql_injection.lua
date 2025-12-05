-- SQL Injection vulnerabilities in Lua
-- Testing LuaSQL, pgmoon, lua-resty-mysql patterns

local luasql = require("luasql.mysql")

-- Test 1: Direct string concatenation in query
function vulnerable_query(user_input)
    local env = luasql.mysql()
    local conn = env:connect("database", "user", "pass")
    -- VULNERABLE: SQL injection via concatenation
    local query = "SELECT * FROM users WHERE name = '" .. user_input .. "'"
    local cursor = conn:execute(query)
    return cursor:fetch()
end

-- Test 2: String format injection
function format_query(id)
    local conn = get_connection()
    -- VULNERABLE: User input in format string
    local query = string.format("SELECT * FROM products WHERE id = %s", id)
    return conn:execute(query)
end

-- Test 3: OpenResty mysql injection
function resty_mysql_query(user_id)
    local mysql = require("resty.mysql")
    local db = mysql:new()
    db:connect({host = "127.0.0.1", port = 3306, database = "test"})
    -- VULNERABLE: Direct interpolation
    local res = db:query("SELECT * FROM users WHERE id = " .. user_id)
    return res
end

-- Test 4: pgmoon PostgreSQL injection
function pgmoon_query(username)
    local pgmoon = require("pgmoon")
    local pg = pgmoon.new({host = "127.0.0.1", database = "test"})
    pg:connect()
    -- VULNERABLE: String concatenation
    local res = pg:query("SELECT * FROM accounts WHERE username = '" .. username .. "'")
    return res
end

-- Test 5: Multiple injections in one query
function multi_param_query(name, email)
    local conn = get_connection()
    -- VULNERABLE: Multiple injection points
    local query = "INSERT INTO users (name, email) VALUES ('" .. name .. "', '" .. email .. "')"
    return conn:execute(query)
end

-- Test 6: Injection in WHERE clause with LIKE
function search_users(search_term)
    local conn = get_connection()
    -- VULNERABLE: LIKE clause injection
    local query = "SELECT * FROM users WHERE name LIKE '%" .. search_term .. "%'"
    return conn:execute(query)
end

-- Test 7: Injection in ORDER BY
function sorted_query(sort_column)
    local conn = get_connection()
    -- VULNERABLE: ORDER BY injection
    local query = "SELECT * FROM products ORDER BY " .. sort_column
    return conn:execute(query)
end

-- Test 8: Injection via table name
function dynamic_table_query(table_name, id)
    local conn = get_connection()
    -- VULNERABLE: Table name injection
    local query = "SELECT * FROM " .. table_name .. " WHERE id = " .. id
    return conn:execute(query)
end

-- Test 9: Second-order injection (data from DB used in query)
function second_order_injection()
    local conn = get_connection()
    local cursor = conn:execute("SELECT username FROM users WHERE id = 1")
    local username = cursor:fetch()
    -- VULNERABLE: Using DB data without sanitization
    local query = "SELECT * FROM logs WHERE user = '" .. username .. "'"
    return conn:execute(query)
end

-- Test 10: Injection in LIMIT clause
function paginated_query(limit, offset)
    local conn = get_connection()
    -- VULNERABLE: LIMIT/OFFSET injection
    local query = "SELECT * FROM products LIMIT " .. limit .. " OFFSET " .. offset
    return conn:execute(query)
end

-- Test 11: ngx.req input to SQL
function openresty_sql_injection()
    local args = ngx.req.get_uri_args()
    local user_id = args.id
    local mysql = require("resty.mysql")
    local db = mysql:new()
    db:connect({host = "127.0.0.1", database = "app"})
    -- VULNERABLE: Request param to SQL
    local res = db:query("SELECT * FROM users WHERE id = " .. user_id)
    ngx.say(res)
end

-- Test 12: Injection in subquery
function subquery_injection(dept)
    local conn = get_connection()
    -- VULNERABLE: Subquery injection
    local query = "SELECT * FROM employees WHERE dept_id IN (SELECT id FROM departments WHERE name = '" .. dept .. "')"
    return conn:execute(query)
end

-- Test 13: Stored procedure injection
function stored_proc_injection(param)
    local conn = get_connection()
    -- VULNERABLE: Stored procedure parameter injection
    local query = "CALL get_user_data('" .. param .. "')"
    return conn:execute(query)
end

-- Helper function (stub)
function get_connection()
    local env = luasql.mysql()
    return env:connect("database", "user", "pass")
end
