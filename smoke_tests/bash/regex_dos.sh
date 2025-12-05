#!/bin/bash
# ReDoS (Regular Expression Denial of Service) vulnerabilities in Bash

# Test 1: grep with user pattern
vulnerable_grep_pattern() {
    local pattern="$1"
    local file="$2"
    # VULNERABLE: User-controlled regex pattern
    grep -E "$pattern" "$file"
}

# Test 2: sed with user pattern
vulnerable_sed_pattern() {
    local pattern="$1"
    local replacement="$2"
    local file="$3"
    # VULNERABLE: User-controlled sed pattern
    sed "s/$pattern/$replacement/g" "$file"
}

# Test 3: awk with user regex
vulnerable_awk_pattern() {
    local pattern="$1"
    local file="$2"
    # VULNERABLE: User-controlled awk pattern
    awk "/$pattern/ {print}" "$file"
}

# Test 4: perl regex via bash
vulnerable_perl_regex() {
    local pattern="$1"
    local input="$2"
    # VULNERABLE: Perl regex with backtracking
    perl -e "print '$input' =~ /$pattern/ ? 'match' : 'no match'"
}

# Test 5: python regex via bash
vulnerable_python_regex() {
    local pattern="$1"
    local input="$2"
    # VULNERABLE: Python regex with catastrophic backtracking
    python -c "import re; re.match('$pattern', '$input')"
}

# Test 6: ruby regex via bash
vulnerable_ruby_regex() {
    local pattern="$1"
    local input="$2"
    # VULNERABLE: Ruby regex
    ruby -e "puts /$pattern/ =~ '$input'"
}

# Test 7: expr with user pattern
vulnerable_expr() {
    local string="$1"
    local pattern="$2"
    # VULNERABLE: User-controlled pattern in expr
    expr "$string" : "$pattern"
}

# Test 8: bash regex match
vulnerable_bash_regex() {
    local input="$1"
    local pattern="$2"
    # VULNERABLE: Bash regex with user pattern
    if [[ "$input" =~ $pattern ]]; then
        echo "matched"
    fi
}

# Test 9: find with regex
vulnerable_find_regex() {
    local pattern="$1"
    local dir="$2"
    # VULNERABLE: User-controlled regex in find
    find "$dir" -regextype posix-extended -regex "$pattern"
}

# Test 10: locate with pattern
vulnerable_locate() {
    local pattern="$1"
    # VULNERABLE: User-controlled pattern
    locate --regex "$pattern"
}

# Test 11: grep -P (PCRE)
vulnerable_grep_pcre() {
    local pattern="$1"
    local file="$2"
    # VULNERABLE: PCRE patterns can be catastrophic
    grep -P "$pattern" "$file"
}

# Test 12: pcregrep with user pattern
vulnerable_pcregrep() {
    local pattern="$1"
    local file="$2"
    # VULNERABLE: PCRE regex
    pcregrep "$pattern" "$file"
}

# Test 13: ripgrep with user pattern
vulnerable_rg() {
    local pattern="$1"
    local dir="$2"
    # VULNERABLE: User-controlled pattern
    rg "$pattern" "$dir"
}

# Test 14: ag (silver searcher) with pattern
vulnerable_ag() {
    local pattern="$1"
    local dir="$2"
    # VULNERABLE: User-controlled pattern
    ag "$pattern" "$dir"
}

# Test 15: node regex via bash
vulnerable_node_regex() {
    local pattern="$1"
    local input="$2"
    # VULNERABLE: JavaScript regex
    node -e "console.log(/$pattern/.test('$input'))"
}

