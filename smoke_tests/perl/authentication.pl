#!/usr/bin/perl
# Authentication vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use Digest::MD5;

my $cgi = CGI->new();

# Test 1: Timing attack vulnerable comparison
sub vulnerable_timing_check {
    my $provided_token = $cgi->param('token');
    my $expected_token = get_secret_token();
    # VULNERABLE: String comparison is timing-vulnerable
    if ($provided_token eq $expected_token) {
        return 1;
    }
    return 0;
}

# Test 2: Plain-text password storage
sub store_password_plaintext {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $dbh = get_dbh();
    # VULNERABLE: Storing password in plain text
    $dbh->do("INSERT INTO users (username, password) VALUES (?, ?)",
        undef, $username, $password);
}

# Test 3: MD5 password hash
sub store_password_md5 {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    # VULNERABLE: MD5 is too weak for passwords
    my $hash = Digest::MD5::md5_hex($password);
    my $dbh = get_dbh();
    $dbh->do("INSERT INTO users (username, password_hash) VALUES (?, ?)",
        undef, $username, $hash);
}

# Test 4: No password length minimum
sub validate_password_weak {
    my $password = shift;
    # VULNERABLE: No minimum length requirement
    if (length($password) > 0) {
        return 1;
    }
    return 0;
}

# Test 5: Hardcoded admin credentials
sub check_admin_credentials {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    # VULNERABLE: Hardcoded admin credentials
    if ($username eq 'admin' && $password eq 'admin123') {
        return 1;
    }
    return 0;
}

# Test 6: Session fixation
sub vulnerable_session_fixation {
    my $session_id = $cgi->param('session_id') || generate_session_id();
    # VULNERABLE: Accepting session ID from user
    set_session_cookie($session_id);
    return $session_id;
}

# Test 7: No session regeneration after login
sub login_no_regeneration {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    if (authenticate($username, $password)) {
        # VULNERABLE: Session not regenerated after login
        set_user_in_session($username);
        return 1;
    }
    return 0;
}

# Test 8: Insecure password reset
sub password_reset_vulnerable {
    my $email = $cgi->param('email');
    # VULNERABLE: Predictable reset token
    my $token = time() . "_" . $email;
    send_reset_email($email, $token);
}

# Test 9: Username enumeration
sub login_with_enumeration {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $dbh = get_dbh();
    my $user = $dbh->selectrow_hashref(
        "SELECT * FROM users WHERE username = ?", undef, $username
    );
    if (!$user) {
        # VULNERABLE: Different error for non-existent user
        return { error => "User not found" };
    }
    if ($user->{password} ne $password) {
        return { error => "Invalid password" };
    }
    return { success => 1 };
}

# Test 10: No account lockout
sub login_no_lockout {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    # VULNERABLE: No rate limiting or lockout
    if (authenticate($username, $password)) {
        return 1;
    }
    return 0;
}

# Test 11: Insecure "remember me"
sub remember_me_insecure {
    my $username = $cgi->param('username');
    if ($cgi->param('remember')) {
        # VULNERABLE: Storing username in cookie for auto-login
        my $cookie = $cgi->cookie(
            -name    => 'remember_user',
            -value   => $username,
            -expires => '+1y'
        );
        print $cgi->header(-cookie => $cookie);
    }
}

# Test 12: Weak session ID generation
sub generate_weak_session {
    # VULNERABLE: Predictable session ID
    my $session_id = time() . "_" . $$;
    return $session_id;
}

# Test 13: Password in URL
sub login_with_get {
    my $username = $cgi->url_param('username');
    my $password = $cgi->url_param('password');
    # VULNERABLE: Credentials in URL (logged, cached, visible)
    if (authenticate($username, $password)) {
        return 1;
    }
    return 0;
}

# Test 14: SQL injection in auth
sub sql_injection_auth {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $dbh = get_dbh();
    # VULNERABLE: SQL injection + authentication bypass
    my $user = $dbh->selectrow_hashref(
        "SELECT * FROM users WHERE username = '$username' AND password = '$password'"
    );
    if ($user) {
        return 1;
    }
    return 0;
}

# Test 15: Insecure cookie attributes
sub set_insecure_session {
    my $session_id = generate_session_id();
    # VULNERABLE: No Secure, HttpOnly, SameSite flags
    my $cookie = $cgi->cookie(
        -name  => 'session',
        -value => $session_id
    );
    print $cgi->header(-cookie => $cookie);
}

# Helper functions
sub get_secret_token { return "secret123"; }
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }
sub generate_session_id { return Digest::MD5::md5_hex(rand()); }
sub set_session_cookie { }
sub authenticate { return 1; }
sub set_user_in_session { }
sub send_reset_email { }

1;
