#!/bin/bash
# NoSQL Injection vulnerabilities in Bash

# Test 1: MongoDB query with user input
vulnerable_mongo_query() {
    local username="$1"
    # VULNERABLE: User input in MongoDB query
    mongo mydb --eval "db.users.find({username: '$username'})"
}

# Test 2: MongoDB with JSON query
vulnerable_mongo_json() {
    local query="$1"
    # VULNERABLE: User-controlled query object
    mongo mydb --eval "db.users.find($query)"
}

# Test 3: mongoimport with user data
vulnerable_mongoimport() {
    local json_file="$1"
    local collection="$2"
    # VULNERABLE: User-controlled collection/data
    mongoimport --db mydb --collection "$collection" --file "$json_file"
}

# Test 4: mongoexport with user filter
vulnerable_mongoexport() {
    local filter="$1"
    # VULNERABLE: User-controlled export filter
    mongoexport --db mydb --collection users --query "$filter"
}

# Test 5: Redis command injection
vulnerable_redis() {
    local key="$1"
    # VULNERABLE: User input in Redis command
    redis-cli GET "$key"
}

# Test 6: Redis with user value
vulnerable_redis_set() {
    local key="$1"
    local value="$2"
    # VULNERABLE: User-controlled key and value
    redis-cli SET "$key" "$value"
}

# Test 7: Redis eval with user script
vulnerable_redis_eval() {
    local script="$1"
    # VULNERABLE: User-controlled Lua script
    redis-cli EVAL "$script" 0
}

# Test 8: CouchDB query
vulnerable_couchdb() {
    local selector="$1"
    # VULNERABLE: User-controlled selector
    curl -X POST "http://localhost:5984/mydb/_find" \
        -H "Content-Type: application/json" \
        -d "{\"selector\": $selector}"
}

# Test 9: Elasticsearch query
vulnerable_elasticsearch() {
    local query="$1"
    # VULNERABLE: User-controlled query
    curl -X GET "http://localhost:9200/myindex/_search" \
        -H "Content-Type: application/json" \
        -d "$query"
}

# Test 10: MongoDB aggregation
vulnerable_mongo_aggregate() {
    local pipeline="$1"
    # VULNERABLE: User-controlled aggregation pipeline
    mongo mydb --eval "db.users.aggregate($pipeline)"
}

# Test 11: MongoDB update with user query
vulnerable_mongo_update() {
    local filter="$1"
    local update="$2"
    # VULNERABLE: User-controlled update
    mongo mydb --eval "db.users.updateMany($filter, $update)"
}

# Test 12: MongoDB delete with user query
vulnerable_mongo_delete() {
    local filter="$1"
    # VULNERABLE: User-controlled deletion
    mongo mydb --eval "db.users.deleteMany($filter)"
}

# Test 13: Redis KEYS pattern
vulnerable_redis_keys() {
    local pattern="$1"
    # VULNERABLE: User-controlled pattern (DoS + info disclosure)
    redis-cli KEYS "$pattern"
}

# Test 14: MongoDB $where injection
vulnerable_mongo_where() {
    local condition="$1"
    # VULNERABLE: JavaScript injection via $where
    mongo mydb --eval "db.users.find({\$where: '$condition'})"
}

# Test 15: DynamoDB query via AWS CLI
vulnerable_dynamodb() {
    local key_condition="$1"
    # VULNERABLE: User-controlled key condition
    aws dynamodb query --table-name Users --key-condition-expression "$key_condition"
}

