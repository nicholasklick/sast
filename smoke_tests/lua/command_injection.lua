-- Command Injection vulnerabilities in Lua

-- Test 1: os.execute with user input
function execute_command(user_input)
    -- VULNERABLE: Direct command execution
    os.execute("ls " .. user_input)
end

-- Test 2: io.popen with user input
function popen_command(filename)
    -- VULNERABLE: Command injection via popen
    local handle = io.popen("cat " .. filename)
    local result = handle:read("*a")
    handle:close()
    return result
end

-- Test 3: Ping command injection
function ping_host(host)
    -- VULNERABLE: Shell injection in ping
    os.execute("ping -c 1 " .. host)
end

-- Test 4: File operations via shell
function delete_file(path)
    -- VULNERABLE: rm command injection
    os.execute("rm -f " .. path)
end

-- Test 5: Grep with user input
function search_logs(pattern)
    -- VULNERABLE: Grep pattern injection
    local handle = io.popen("grep " .. pattern .. " /var/log/app.log")
    return handle:read("*a")
end

-- Test 6: Curl command injection
function fetch_url(url)
    -- VULNERABLE: URL injection in curl
    local handle = io.popen("curl -s " .. url)
    return handle:read("*a")
end

-- Test 7: Multiple commands via semicolon
function process_file(filename)
    -- VULNERABLE: Can inject additional commands
    os.execute("cat " .. filename .. " | wc -l")
end

-- Test 8: Command in string.format
function format_command(arg)
    -- VULNERABLE: Format string command injection
    local cmd = string.format("echo %s", arg)
    os.execute(cmd)
end

-- Test 9: OpenResty command injection
function openresty_exec()
    local args = ngx.req.get_uri_args()
    local file = args.file
    -- VULNERABLE: Request param to command
    local handle = io.popen("cat " .. file)
    ngx.say(handle:read("*a"))
end

-- Test 10: Environment variable in command
function env_command()
    local path = os.getenv("USER_PATH")
    -- VULNERABLE: Environment variable in command
    os.execute("ls " .. path)
end

-- Test 11: Command with backticks simulation
function backtick_sim(cmd)
    -- VULNERABLE: Arbitrary command execution
    local handle = io.popen(cmd)
    return handle:read("*a")
end

-- Test 12: Chained commands
function chained_commands(dir, file)
    -- VULNERABLE: Multiple injection points
    os.execute("cd " .. dir .. " && cat " .. file)
end

-- Test 13: Command with pipes
function piped_command(input)
    -- VULNERABLE: Pipe injection
    local handle = io.popen("echo " .. input .. " | base64")
    return handle:read("*a")
end
