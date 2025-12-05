#!/bin/bash
# Environment Variable Injection vulnerabilities in Bash

# Test 1: LD_PRELOAD injection
vulnerable_ld_preload() {
    local lib="$1"
    # VULNERABLE: Library injection
    LD_PRELOAD="$lib" /usr/bin/target_app
}

# Test 2: PATH injection
vulnerable_path() {
    local new_path="$1"
    # VULNERABLE: Path manipulation
    PATH="$new_path:$PATH"
    ls
}

# Test 3: IFS manipulation
vulnerable_ifs() {
    local ifs="$1"
    # VULNERABLE: IFS injection
    IFS="$ifs"
    read -a arr <<< "data"
}

# Test 4: PYTHONPATH injection
vulnerable_pythonpath() {
    local pypath="$1"
    # VULNERABLE: Python path injection
    PYTHONPATH="$pypath" python script.py
}

# Test 5: NODE_PATH injection
vulnerable_nodepath() {
    local nodepath="$1"
    # VULNERABLE: Node.js module path injection
    NODE_PATH="$nodepath" node app.js
}

# Test 6: LD_LIBRARY_PATH injection
vulnerable_ld_library() {
    local libpath="$1"
    # VULNERABLE: Library path injection
    LD_LIBRARY_PATH="$libpath" ./binary
}

# Test 7: RUBYLIB injection
vulnerable_rubylib() {
    local rubylib="$1"
    # VULNERABLE: Ruby library injection
    RUBYLIB="$rubylib" ruby script.rb
}

# Test 8: PERL5LIB injection
vulnerable_perllib() {
    local perllib="$1"
    # VULNERABLE: Perl library injection
    PERL5LIB="$perllib" perl script.pl
}

# Test 9: CLASSPATH injection
vulnerable_classpath() {
    local classpath="$1"
    # VULNERABLE: Java classpath injection
    CLASSPATH="$classpath" java Main
}

# Test 10: HOME directory manipulation
vulnerable_home() {
    local home="$1"
    # VULNERABLE: Home directory injection
    HOME="$home" ./app
}

# Test 11: TMPDIR manipulation
vulnerable_tmpdir() {
    local tmpdir="$1"
    # VULNERABLE: Temp directory injection
    TMPDIR="$tmpdir" mktemp
}

# Test 12: LC_ALL locale injection
vulnerable_locale() {
    local locale="$1"
    # VULNERABLE: Locale injection
    LC_ALL="$locale" sort file.txt
}

# Test 13: HTTP_PROXY injection
vulnerable_proxy() {
    local proxy="$1"
    # VULNERABLE: Proxy injection for data exfil
    HTTP_PROXY="$proxy" curl http://example.com
}

# Test 14: GIT_SSH_COMMAND injection
vulnerable_git_ssh() {
    local cmd="$1"
    # VULNERABLE: Git SSH command injection
    GIT_SSH_COMMAND="$cmd" git clone repo
}

# Test 15: AWS credential injection
vulnerable_aws_creds() {
    local key="$1"
    local secret="$2"
    # VULNERABLE: AWS credential injection
    AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret" aws s3 ls
}

