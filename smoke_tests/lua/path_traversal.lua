-- Path Traversal vulnerabilities in Lua

-- Test 1: Direct file read with user path
function read_file(user_path)
    -- VULNERABLE: No path validation
    local file = io.open(user_path, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
end

-- Test 2: File write with user path
function write_file(user_path, content)
    -- VULNERABLE: Writing to arbitrary path
    local file = io.open(user_path, "w")
    if file then
        file:write(content)
        file:close()
    end
end

-- Test 3: Path concatenation
function get_user_file(username, filename)
    -- VULNERABLE: Path traversal via filename
    local path = "/data/users/" .. username .. "/" .. filename
    return io.open(path, "r")
end

-- Test 4: loadfile with user input
function load_user_script(script_name)
    -- VULNERABLE: Loading script from user-controlled path
    local path = "./scripts/" .. script_name
    return loadfile(path)
end

-- Test 5: dofile with user path
function execute_plugin(plugin_name)
    -- VULNERABLE: Executing arbitrary Lua file
    local path = "./plugins/" .. plugin_name .. ".lua"
    dofile(path)
end

-- Test 6: File deletion
function delete_user_file(filename)
    -- VULNERABLE: Deleting arbitrary files
    os.remove("./uploads/" .. filename)
end

-- Test 7: File rename/move
function move_file(old_name, new_name)
    -- VULNERABLE: Moving files to arbitrary locations
    os.rename("./temp/" .. old_name, "./storage/" .. new_name)
end

-- Test 8: Directory listing via command
function list_directory(dir)
    -- VULNERABLE: Path traversal in directory listing
    local handle = io.popen("ls " .. dir)
    return handle:read("*a")
end

-- Test 9: OpenResty file read
function openresty_file_read()
    local args = ngx.req.get_uri_args()
    local filename = args.file
    -- VULNERABLE: Request param to file path
    local file = io.open("/var/www/html/" .. filename, "r")
    if file then
        ngx.say(file:read("*a"))
        file:close()
    end
end

-- Test 10: io.lines with user path
function read_lines(filepath)
    -- VULNERABLE: Iterating arbitrary file
    for line in io.lines(filepath) do
        print(line)
    end
end

-- Test 11: io.input with user path
function set_input_file(path)
    -- VULNERABLE: Setting arbitrary input file
    io.input(path)
    return io.read("*a")
end

-- Test 12: require path manipulation
function load_module(module_path)
    -- VULNERABLE: Module path traversal
    package.path = package.path .. ";" .. module_path .. "/?.lua"
    return require("target")
end

-- Test 13: Zip extraction path (conceptual)
function extract_file(archive, target_dir, entry_name)
    -- VULNERABLE: Zip slip - entry_name could contain ../
    local output_path = target_dir .. "/" .. entry_name
    local file = io.open(output_path, "wb")
    -- Extract entry to file...
end
