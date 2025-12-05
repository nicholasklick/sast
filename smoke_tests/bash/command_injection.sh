#!/bin/bash
# Command Injection vulnerabilities in Bash

# Test 1: eval with user input
vulnerable_eval() {
    local user_input="$1"
    # VULNERABLE: Direct eval of user input
    eval "$user_input"
}

# Test 2: Unquoted variable expansion
vulnerable_unquoted() {
    local filename="$1"
    # VULNERABLE: Unquoted variable allows command injection
    rm $filename
}

# Test 3: Backtick command substitution with user input
vulnerable_backticks() {
    local cmd="$1"
    # VULNERABLE: Command substitution with user input
    result=`$cmd`
    echo "$result"
}

# Test 4: $() command substitution with user input
vulnerable_command_sub() {
    local user_cmd="$1"
    # VULNERABLE: Command substitution
    output=$($user_cmd)
    echo "$output"
}

# Test 5: xargs with user input
vulnerable_xargs() {
    local pattern="$1"
    # VULNERABLE: xargs can execute commands
    echo "$pattern" | xargs rm
}

# Test 6: find -exec with user input
vulnerable_find_exec() {
    local dir="$1"
    # VULNERABLE: find with user-controlled path
    find "$dir" -exec rm {} \;
}

# Test 7: Arithmetic evaluation
vulnerable_arithmetic() {
    local expr="$1"
    # VULNERABLE: Arithmetic expansion can execute commands
    result=$((expr))
    echo "$result"
}

# Test 8: source/dot with user path
vulnerable_source() {
    local script_path="$1"
    # VULNERABLE: Sourcing user-controlled file
    source "$script_path"
}

# Test 9: bash -c with user input
vulnerable_bash_c() {
    local code="$1"
    # VULNERABLE: Executing user input as bash code
    bash -c "$code"
}

# Test 10: ssh with user-controlled command
vulnerable_ssh() {
    local host="$1"
    local cmd="$2"
    # VULNERABLE: SSH command injection
    ssh "$host" "$cmd"
}

# Test 11: sudo with user input
vulnerable_sudo() {
    local command="$1"
    # VULNERABLE: Sudo with user command
    sudo $command
}

# Test 12: Variable in command position
vulnerable_cmd_variable() {
    local program="$1"
    # VULNERABLE: User-controlled program execution
    $program --version
}

# Test 13: Subshell execution
vulnerable_subshell() {
    local cmd="$1"
    # VULNERABLE: Subshell with user input
    (eval "$cmd")
}

# Test 14: Process substitution
vulnerable_process_sub() {
    local cmd="$1"
    # VULNERABLE: Process substitution
    cat <($cmd)
}

# Test 15: Here-string with command
vulnerable_herestring() {
    local data="$1"
    # VULNERABLE: Data could contain shell escapes
    bash <<< "$data"
}

# Test 16: Curl piped to bash
vulnerable_curl_bash() {
    local url="$1"
    # VULNERABLE: Remote code execution
    curl -s "$url" | bash
}

# Test 17: wget and execute
vulnerable_wget_exec() {
    local url="$1"
    # VULNERABLE: Download and execute
    wget -O - "$url" | sh
}

# Test 18: Array expansion injection
vulnerable_array() {
    local input="$1"
    # VULNERABLE: Array elements can contain commands
    arr=($input)
    "${arr[@]}"
}
