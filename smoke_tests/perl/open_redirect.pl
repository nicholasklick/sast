#!/usr/bin/perl
# Open Redirect vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: Direct redirect from parameter
sub vulnerable_redirect {
    my $url = $cgi->param('url');
    # VULNERABLE: Open redirect
    print $cgi->redirect($url);
}

# Test 2: Location header injection
sub vulnerable_location_header {
    my $next = $cgi->param('next');
    # VULNERABLE: Open redirect via header
    print "Status: 302 Found\n";
    print "Location: $next\n\n";
}

# Test 3: Meta refresh redirect
sub vulnerable_meta_refresh {
    my $target = $cgi->param('target');
    print $cgi->header();
    # VULNERABLE: Meta refresh redirect
    print "<html><head>";
    print "<meta http-equiv='refresh' content='0;url=$target'>";
    print "</head><body>Redirecting...</body></html>";
}

# Test 4: JavaScript redirect
sub vulnerable_js_redirect {
    my $destination = $cgi->param('destination');
    print $cgi->header();
    # VULNERABLE: JavaScript redirect
    print "<script>window.location.href='$destination';</script>";
}

# Test 5: Redirect with path parameter
sub vulnerable_path_redirect {
    my $path = $cgi->param('path');
    # VULNERABLE: Path-based redirect (can use //)
    print $cgi->redirect("/$path");
}

# Test 6: Base URL concatenation
sub vulnerable_base_url {
    my $path = $cgi->param('return_path');
    my $base_url = "https://example.com";
    # VULNERABLE: Can be bypassed with //evil.com
    print $cgi->redirect("$base_url$path");
}

# Test 7: Redirect after login
sub vulnerable_login_redirect {
    my $username = $cgi->param('username');
    my $password = $cgi->param('password');
    my $redirect_to = $cgi->param('redirect_to');

    if (authenticate($username, $password)) {
        # VULNERABLE: Post-login redirect
        print $cgi->redirect($redirect_to);
    }
}

# Test 8: Referer-based redirect
sub vulnerable_referer_redirect {
    my $referer = $ENV{HTTP_REFERER};
    # VULNERABLE: Referer-based redirect
    print $cgi->redirect($referer);
}

# Test 9: Cookie-based redirect
sub vulnerable_cookie_redirect {
    my $saved_url = $cgi->cookie('saved_url');
    # VULNERABLE: Cookie-controlled redirect
    print $cgi->redirect($saved_url);
}

# Test 10: Regex bypass redirect
sub vulnerable_regex_redirect {
    my $url = $cgi->param('url');
    # VULNERABLE: Weak regex validation
    if ($url =~ /^https?:\/\/example\.com/) {
        print $cgi->redirect($url);
    }
}

# Test 11: Subdomain redirect bypass
sub vulnerable_subdomain_redirect {
    my $url = $cgi->param('url');
    # VULNERABLE: Can be bypassed with evil.example.com.attacker.com
    if ($url =~ /example\.com/) {
        print $cgi->redirect($url);
    }
}

# Test 12: URL from database
sub vulnerable_db_redirect {
    my $id = $cgi->param('id');
    my $dbh = get_dbh();
    my ($url) = $dbh->selectrow_array(
        "SELECT redirect_url FROM shortcuts WHERE id = ?", undef, $id
    );
    # VULNERABLE: Redirect to user-stored URL
    print $cgi->redirect($url);
}

# Test 13: OAuth callback redirect
sub vulnerable_oauth_redirect {
    my $redirect_uri = $cgi->param('redirect_uri');
    my $code = generate_auth_code();
    # VULNERABLE: OAuth redirect
    print $cgi->redirect("$redirect_uri?code=$code");
}

# Test 14: Error page redirect
sub vulnerable_error_redirect {
    my $error_url = $cgi->param('error_url');
    # VULNERABLE: Error redirect
    print $cgi->redirect("$error_url?error=access_denied");
}

# Test 15: Logout redirect
sub vulnerable_logout_redirect {
    my $return_url = $cgi->param('return');
    clear_session();
    # VULNERABLE: Post-logout redirect
    print $cgi->redirect($return_url);
}

# Helper functions
sub authenticate { return 1; }
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }
sub generate_auth_code { return "abc123"; }
sub clear_session { }

1;
