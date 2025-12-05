#!/usr/bin/perl
# SQL Injection vulnerabilities in Perl (DBI)

use strict;
use warnings;
use DBI;
use CGI;

my $cgi = CGI->new();
my $dbh = DBI->connect("dbi:mysql:database=test", "user", "pass");

# Test 1: Direct string interpolation in do()
sub vulnerable_do {
    my $id = $cgi->param('id');
    # VULNERABLE: SQL injection via do()
    $dbh->do("DELETE FROM users WHERE id = $id");
}

# Test 2: prepare() with string interpolation
sub vulnerable_prepare {
    my $username = $cgi->param('username');
    # VULNERABLE: SQL injection in prepare
    my $sth = $dbh->prepare("SELECT * FROM users WHERE username = '$username'");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# Test 3: selectrow_array with interpolation
sub vulnerable_selectrow_array {
    my $email = $cgi->param('email');
    # VULNERABLE: SQL injection
    my @row = $dbh->selectrow_array(
        "SELECT id, name FROM users WHERE email = '$email'"
    );
    return @row;
}

# Test 4: selectrow_hashref
sub vulnerable_selectrow_hashref {
    my $id = $cgi->param('id');
    # VULNERABLE: SQL injection
    my $row = $dbh->selectrow_hashref(
        "SELECT * FROM products WHERE id = $id"
    );
    return $row;
}

# Test 5: selectall_arrayref
sub vulnerable_selectall {
    my $category = $cgi->param('category');
    # VULNERABLE: SQL injection
    my $rows = $dbh->selectall_arrayref(
        "SELECT * FROM products WHERE category = '$category'"
    );
    return $rows;
}

# Test 6: selectcol_arrayref
sub vulnerable_selectcol {
    my $status = $cgi->param('status');
    # VULNERABLE: SQL injection
    my $ids = $dbh->selectcol_arrayref(
        "SELECT id FROM orders WHERE status = '$status'"
    );
    return $ids;
}

# Test 7: LIKE clause injection
sub vulnerable_like {
    my $search = $cgi->param('search');
    # VULNERABLE: SQL injection in LIKE
    my $sth = $dbh->prepare("SELECT * FROM products WHERE name LIKE '%$search%'");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# Test 8: ORDER BY injection
sub vulnerable_order_by {
    my $sort = $cgi->param('sort');
    # VULNERABLE: SQL injection in ORDER BY
    my $sth = $dbh->prepare("SELECT * FROM products ORDER BY $sort");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# Test 9: Table name injection
sub vulnerable_table_name {
    my $table = $cgi->param('table');
    # VULNERABLE: SQL injection via table name
    my $sth = $dbh->prepare("SELECT * FROM $table");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# Test 10: Column name injection
sub vulnerable_column_name {
    my $column = $cgi->param('column');
    # VULNERABLE: SQL injection via column name
    my $sth = $dbh->prepare("SELECT $column FROM users");
    $sth->execute();
    return $sth->fetchall_arrayref();
}

# Test 11: Multiple parameter injection
sub vulnerable_multiple_params {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    # VULNERABLE: Classic login bypass
    my $sth = $dbh->prepare(
        "SELECT * FROM users WHERE username = '$username' AND password = '$password'"
    );
    $sth->execute();
    return $sth->fetchrow_hashref();
}

# Test 12: INSERT injection
sub vulnerable_insert {
    my $name = $cgi->param('name');
    my $email = $cgi->param('email');
    # VULNERABLE: SQL injection in INSERT
    $dbh->do("INSERT INTO users (name, email) VALUES ('$name', '$email')");
}

# Test 13: UPDATE injection
sub vulnerable_update {
    my $id = $cgi->param('id');
    my $status = $cgi->param('status');
    # VULNERABLE: SQL injection in UPDATE
    $dbh->do("UPDATE orders SET status = '$status' WHERE id = $id");
}

# Test 14: Stored procedure injection
sub vulnerable_stored_proc {
    my $param = $cgi->param('param');
    # VULNERABLE: SQL injection in stored procedure call
    $dbh->do("CALL process_order('$param')");
}

# Test 15: execute with interpolated value
sub vulnerable_execute {
    my $id = $cgi->param('id');
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    # Still vulnerable if id is not validated
    $sth->execute($id);
    return $sth->fetchrow_hashref();
}

1;
