#!/bin/bash
# Unsafe Deserialization vulnerabilities in Bash

# Test 1: pickle via Python call
vulnerable_pickle() {
    local data="$1"
    # VULNERABLE: Pickle deserialization
    echo "$data" | python -c "import pickle,sys; pickle.loads(sys.stdin.buffer.read())"
}

# Test 2: yaml.load unsafe
vulnerable_yaml() {
    local file="$1"
    # VULNERABLE: Unsafe YAML load
    python -c "import yaml; yaml.load(open('$file'))"
}

# Test 3: eval of JSON-like data
vulnerable_json_eval() {
    local json="$1"
    # VULNERABLE: eval instead of jq
    eval "data=$json"
}

# Test 4: PHP unserialize
vulnerable_php_unserialize() {
    local data="$1"
    # VULNERABLE: PHP object injection
    php -r "unserialize('$data');"
}

# Test 5: Ruby Marshal
vulnerable_ruby_marshal() {
    local data="$1"
    # VULNERABLE: Ruby deserialization
    echo "$data" | ruby -e "Marshal.load(STDIN.read)"
}

# Test 6: Perl Storable
vulnerable_perl_storable() {
    local file="$1"
    # VULNERABLE: Perl deserialization
    perl -MStorable -e "Storable::retrieve('$file')"
}

# Test 7: Java ObjectInputStream
vulnerable_java_deserialize() {
    local file="$1"
    # VULNERABLE: Java deserialization (via class)
    java DeserializeObject "$file"
}

# Test 8: Node.js eval of JSON
vulnerable_node_eval() {
    local data="$1"
    # VULNERABLE: eval instead of JSON.parse
    node -e "eval('var obj = ' + '$data')"
}

# Test 9: XML entity expansion
vulnerable_xml() {
    local xml="$1"
    # VULNERABLE: XXE via external entities
    xmllint --noent "$xml"
}

# Test 10: Base64 decode and execute
vulnerable_b64_exec() {
    local encoded="$1"
    # VULNERABLE: Execute decoded data
    echo "$encoded" | base64 -d | bash
}

# Test 11: Gzip decompress and execute
vulnerable_gzip_exec() {
    local file="$1"
    # VULNERABLE: Execute decompressed data
    zcat "$file" | bash
}

# Test 12: Tar with execution
vulnerable_tar_exec() {
    local archive="$1"
    # VULNERABLE: Extract and execute
    tar xf "$archive" -C /tmp
    /tmp/extracted/run.sh
}

# Test 13: MessagePack deserialization
vulnerable_msgpack() {
    local data="$1"
    # VULNERABLE: MessagePack with code execution
    python -c "import msgpack; msgpack.unpackb(b'$data', raw=False)"
}

# Test 14: BSON deserialization
vulnerable_bson() {
    local data="$1"
    # VULNERABLE: BSON with potential injection
    python -c "import bson; bson.loads(b'$data')"
}

# Test 15: Read and source
vulnerable_source_data() {
    local file="$1"
    # VULNERABLE: Sourcing untrusted data
    source "$file"
}

