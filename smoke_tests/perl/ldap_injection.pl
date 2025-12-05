#!/usr/bin/perl
# LDAP Injection vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use Net::LDAP;

my $cgi = CGI->new();

# Test 1: LDAP search with user input
sub vulnerable_ldap_search {
    my $username = $cgi->param('username');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind('cn=admin,dc=example,dc=com', password => 'adminpass');
    # VULNERABLE: LDAP injection in search filter
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "(uid=$username)"
    );
    return $mesg->entries;
}

# Test 2: LDAP authentication bypass
sub vulnerable_ldap_auth {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $ldap = Net::LDAP->new('ldap.example.com');
    # VULNERABLE: LDAP injection in bind DN
    my $dn = "uid=$username,ou=users,dc=example,dc=com";
    my $mesg = $ldap->bind($dn, password => $password);
    return !$mesg->code;
}

# Test 3: Complex filter injection
sub vulnerable_complex_filter {
    my $email = $cgi->param('email');
    my $department = $cgi->param('department');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Multiple injection points
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "(&(mail=$email)(department=$department))"
    );
    return $mesg->entries;
}

# Test 4: LDAP modify with user input
sub vulnerable_ldap_modify {
    my $username = $cgi->param('username');
    my $new_email = $cgi->param('email');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind('cn=admin,dc=example,dc=com', password => 'adminpass');
    # VULNERABLE: LDAP injection in modify
    my $mesg = $ldap->modify(
        "uid=$username,ou=users,dc=example,dc=com",
        replace => { mail => $new_email }
    );
    return $mesg;
}

# Test 5: LDAP add with user input
sub vulnerable_ldap_add {
    my $username = $cgi->param('username');
    my $email = $cgi->param('email');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind('cn=admin,dc=example,dc=com', password => 'adminpass');
    # VULNERABLE: LDAP injection in add
    my $mesg = $ldap->add(
        "uid=$username,ou=users,dc=example,dc=com",
        attr => [
            objectClass => ['person', 'inetOrgPerson'],
            cn          => $username,
            mail        => $email,
        ]
    );
    return $mesg;
}

# Test 6: LDAP delete with user input
sub vulnerable_ldap_delete {
    my $username = $cgi->param('username');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind('cn=admin,dc=example,dc=com', password => 'adminpass');
    # VULNERABLE: LDAP injection in delete
    my $mesg = $ldap->delete("uid=$username,ou=users,dc=example,dc=com");
    return $mesg;
}

# Test 7: Wildcard injection
sub vulnerable_wildcard_search {
    my $search = $cgi->param('search');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Wildcard can expose all entries
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "(cn=*$search*)"
    );
    return $mesg->entries;
}

# Test 8: OR condition injection
sub vulnerable_or_injection {
    my $group = $cgi->param('group');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Can inject OR conditions to bypass filters
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "(|(memberOf=cn=$group,ou=groups,dc=example,dc=com)(admin=true))"
    );
    return $mesg->entries;
}

# Test 9: Attribute injection
sub vulnerable_attribute_search {
    my $attribute = $cgi->param('attr');
    my $value = $cgi->param('value');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Attribute name injection
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "($attribute=$value)"
    );
    return $mesg->entries;
}

# Test 10: Base DN injection
sub vulnerable_base_dn {
    my $org = $cgi->param('org');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Base DN injection
    my $mesg = $ldap->search(
        base   => "ou=$org,dc=example,dc=com",
        filter => "(objectClass=person)"
    );
    return $mesg->entries;
}

# Test 11: Password in filter (information disclosure)
sub vulnerable_password_in_filter {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Password comparison in filter
    my $mesg = $ldap->search(
        base   => 'dc=example,dc=com',
        filter => "(&(uid=$username)(userPassword=$password))"
    );
    return $mesg->entries;
}

# Test 12: Compare operation injection
sub vulnerable_ldap_compare {
    my $username = $cgi->param('username');
    my $attribute = $cgi->param('attr');
    my $value = $cgi->param('value');
    my $ldap = Net::LDAP->new('ldap.example.com');
    $ldap->bind();
    # VULNERABLE: Compare with user-controlled attribute
    my $mesg = $ldap->compare(
        "uid=$username,ou=users,dc=example,dc=com",
        attr  => $attribute,
        value => $value
    );
    return $mesg;
}

1;
