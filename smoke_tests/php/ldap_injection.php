<?php
// LDAP Injection vulnerabilities in PHP

define('LDAP_HOST', 'ldap.example.com');
define('LDAP_BASE', 'dc=example,dc=com');

// Test 1: Authentication bypass
function ldap_authenticate() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $ldap = ldap_connect(LDAP_HOST);
    // VULNERABLE: User input in LDAP filter
    $filter = "(&(uid=$username)(userPassword=$password))";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    $entries = ldap_get_entries($ldap, $result);

    return $entries['count'] > 0;
}

// Test 2: User search injection
function search_user() {
    $query = $_GET['query'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Search query from user
    $filter = "(|(cn=*$query*)(mail=*$query*))";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_get_entries($ldap, $result);
}

// Test 3: Group membership check
function check_group() {
    $user = $_GET['user'];
    $group = $_GET['group'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Both parameters from user
    $filter = "(&(member=$user)(cn=$group))";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_count_entries($ldap, $result) > 0;
}

// Test 4: Email lookup
function find_by_email() {
    $email = $_GET['email'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Email from user
    $filter = "(mail=$email)";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_get_entries($ldap, $result);
}

// Test 5: Wildcard injection
function wildcard_search() {
    $prefix = $_GET['prefix'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Wildcard with user input
    $filter = "(cn=$prefix*)";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_count_entries($ldap, $result);
}

// Test 6: DN manipulation
function get_entry() {
    $dn = $_GET['dn'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: DN from user input
    $result = ldap_read($ldap, $dn, "(objectClass=*)");
    return ldap_get_entries($ldap, $result);
}

// Test 7: Attribute modification
function update_attribute() {
    $user = $_POST['user'];
    $description = $_POST['description'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap, 'admin', 'password');

    $dn = "cn=$user," . LDAP_BASE;
    // VULNERABLE: Description value from user
    ldap_modify($ldap, $dn, ['description' => $description]);
}

// Test 8: OR clause injection
function multi_search() {
    $term = $_GET['term'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Term in OR filter
    $filter = "(|(cn=$term)(sn=$term)(mail=$term))";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_count_entries($ldap, $result);
}

// Test 9: Bind with user credentials
function bind_user() {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $ldap = ldap_connect(LDAP_HOST);
    // VULNERABLE: DN constructed from user input
    $dn = "cn=$username," . LDAP_BASE;

    if (@ldap_bind($ldap, $dn, $password)) {
        return true;
    }
    return false;
}

// Test 10: Multiple filter parameters
function advanced_search() {
    $name = $_GET['name'];
    $role = $_GET['role'];
    $status = $_GET['status'];

    $ldap = ldap_connect(LDAP_HOST);
    ldap_bind($ldap);
    // VULNERABLE: Multiple injection points
    $filter = "(&(cn=$name)(role=$role)(status=$status))";
    $result = ldap_search($ldap, LDAP_BASE, $filter);
    return ldap_get_entries($ldap, $result);
}
?>
