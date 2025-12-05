#!/bin/bash
# LDAP Injection vulnerabilities in Bash

# Test 1: ldapsearch with user filter
vulnerable_ldapsearch() {
    local username="$1"
    # VULNERABLE: User input in LDAP filter
    ldapsearch -x -b "dc=example,dc=com" "(uid=$username)"
}

# Test 2: ldapsearch with multiple attributes
vulnerable_ldapsearch_attrs() {
    local filter="$1"
    # VULNERABLE: User-controlled filter
    ldapsearch -x -b "dc=example,dc=com" "$filter" cn mail
}

# Test 3: ldapmodify with user DN
vulnerable_ldapmodify() {
    local user_dn="$1"
    local new_password="$2"
    # VULNERABLE: User-controlled DN
    ldapmodify -x -D "cn=admin,dc=example,dc=com" -w secret << EOF
dn: $user_dn
changetype: modify
replace: userPassword
userPassword: $new_password
EOF
}

# Test 4: ldapadd with user input
vulnerable_ldapadd() {
    local username="$1"
    local email="$2"
    # VULNERABLE: User input in LDIF
    ldapadd -x -D "cn=admin,dc=example,dc=com" -w secret << EOF
dn: uid=$username,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
cn: $username
sn: User
mail: $email
EOF
}

# Test 5: ldapdelete with user DN
vulnerable_ldapdelete() {
    local user_dn="$1"
    # VULNERABLE: User-controlled DN for deletion
    ldapdelete -x -D "cn=admin,dc=example,dc=com" -w secret "$user_dn"
}

# Test 6: ldapcompare with user attribute
vulnerable_ldapcompare() {
    local username="$1"
    local group="$2"
    # VULNERABLE: User input in comparison
    ldapcompare -x "cn=$group,ou=groups,dc=example,dc=com" "member=uid=$username,ou=users,dc=example,dc=com"
}

# Test 7: ldapwhoami with user bind
vulnerable_ldapwhoami() {
    local user_dn="$1"
    local password="$2"
    # VULNERABLE: User credentials in command
    ldapwhoami -x -D "$user_dn" -w "$password"
}

# Test 8: ldappasswd with user DN
vulnerable_ldappasswd() {
    local user_dn="$1"
    local new_pass="$2"
    # VULNERABLE: User-controlled password change
    ldappasswd -x -D "cn=admin,dc=example,dc=com" -w secret -s "$new_pass" "$user_dn"
}

# Test 9: Python ldap via bash
vulnerable_python_ldap() {
    local search_filter="$1"
    # VULNERABLE: LDAP injection via Python
    python -c "
import ldap
l = ldap.initialize('ldap://localhost')
l.simple_bind_s('cn=admin,dc=example,dc=com', 'secret')
l.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, '$search_filter')
"
}

# Test 10: PHP ldap via bash
vulnerable_php_ldap() {
    local username="$1"
    # VULNERABLE: LDAP injection via PHP
    php -r "
\$ldap = ldap_connect('localhost');
ldap_bind(\$ldap, 'cn=admin,dc=example,dc=com', 'secret');
ldap_search(\$ldap, 'dc=example,dc=com', '(uid=$username)');
"
}

# Test 11: ldapsearch OR injection
vulnerable_or_injection() {
    local search="$1"
    # VULNERABLE: OR filter injection
    ldapsearch -x -b "dc=example,dc=com" "(|(cn=$search)(mail=$search))"
}

# Test 12: ldapsearch AND injection
vulnerable_and_injection() {
    local username="$1"
    local department="$2"
    # VULNERABLE: AND filter injection
    ldapsearch -x -b "dc=example,dc=com" "(&(uid=$username)(department=$department))"
}

# Test 13: ldapsearch wildcard
vulnerable_wildcard() {
    local pattern="$1"
    # VULNERABLE: Wildcard injection
    ldapsearch -x -b "dc=example,dc=com" "(cn=$pattern*)"
}

# Test 14: ldapsearch base DN injection
vulnerable_base_dn() {
    local base="$1"
    # VULNERABLE: Base DN injection
    ldapsearch -x -b "$base" "(objectClass=*)"
}

# Test 15: LDAP URL injection
vulnerable_ldap_url() {
    local host="$1"
    # VULNERABLE: LDAP URL injection
    ldapsearch -H "ldap://$host" -x -b "dc=example,dc=com" "(objectClass=*)"
}

