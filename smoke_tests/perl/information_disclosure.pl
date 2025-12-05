#!/usr/bin/perl
# Information Disclosure vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use Data::Dumper;

my $cgi = CGI->new();

# Test 1: Stack trace in error
sub vulnerable_stack_trace {
    eval {
        die "Something went wrong";
    };
    if ($@) {
        print $cgi->header('text/html');
        # VULNERABLE: Exposing stack trace
        print "<pre>$@</pre>";
    }
}

# Test 2: Carp::confess exposure
sub vulnerable_confess {
    use Carp;
    eval {
        confess "Database connection failed";
    };
    if ($@) {
        print $cgi->header('text/html');
        # VULNERABLE: Full stack trace with local variables
        print "<pre>$@</pre>";
    }
}

# Test 3: Data::Dumper output
sub vulnerable_data_dumper {
    my $id = $cgi->param('id');
    my $user = get_user($id);
    print $cgi->header('text/html');
    # VULNERABLE: Dumping internal data structure
    print "<pre>" . Dumper($user) . "</pre>";
}

# Test 4: Environment variable exposure
sub vulnerable_env_exposure {
    print $cgi->header('text/html');
    print "<h1>Debug Info</h1><pre>";
    # VULNERABLE: Exposing all environment variables
    foreach my $key (sort keys %ENV) {
        print "$key = $ENV{$key}\n";
    }
    print "</pre>";
}

# Test 5: Database error exposure
sub vulnerable_db_error {
    my $dbh = get_dbh();
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    unless ($sth->execute($cgi->param('id'))) {
        print $cgi->header('text/html');
        # VULNERABLE: Database error exposure
        print "Error: " . $dbh->errstr;
    }
}

# Test 6: File path disclosure
sub vulnerable_path_disclosure {
    my $file = $cgi->param('file');
    unless (-e "/var/www/files/$file") {
        print $cgi->header('text/html');
        # VULNERABLE: Full path disclosure
        print "File not found: /var/www/files/$file";
    }
}

# Test 7: Server info in headers
sub vulnerable_server_headers {
    print "Content-Type: text/html\n";
    # VULNERABLE: Server info disclosure
    print "X-Powered-By: Perl/$]\n";
    print "Server: Apache/2.4.41 (Ubuntu)\n\n";
    print "Hello";
}

# Test 8: Source code disclosure via __DATA__
sub vulnerable_source_disclosure {
    my $show_debug = $cgi->param('debug');
    if ($show_debug) {
        print $cgi->header('text/plain');
        # VULNERABLE: Exposing source code
        open(my $fh, '<', $0);
        print while <$fh>;
        close($fh);
    }
}

# Test 9: Session data exposure
sub vulnerable_session_exposure {
    my $session = get_session();
    print $cgi->header('text/html');
    # VULNERABLE: Exposing session internals
    print "<pre>" . Dumper($session) . "</pre>";
}

# Test 10: Config file exposure
sub vulnerable_config_exposure {
    print $cgi->header('text/plain');
    # VULNERABLE: Exposing config with credentials
    open(my $fh, '<', '/etc/myapp/config.ini');
    print while <$fh>;
    close($fh);
}

# Test 11: Debug mode enabled
sub vulnerable_debug_mode {
    use CGI::Carp qw(fatalsToBrowser warningsToBrowser);
    # VULNERABLE: Debug info sent to browser
    warningsToBrowser(1);
    warn "Processing request for user " . $cgi->param('user');
}

# Test 12: Version disclosure
sub vulnerable_version_disclosure {
    print $cgi->header('text/html');
    # VULNERABLE: Version information exposure
    print "Running Perl $^V on $^O\n";
    print "CGI.pm version: " . $CGI::VERSION . "\n";
}

# Test 13: Detailed 404 with path
sub vulnerable_404_disclosure {
    my $path = $cgi->path_info();
    unless (-e "/var/www/html$path") {
        print $cgi->header(-status => '404 Not Found');
        # VULNERABLE: Path and server info in 404
        print "404: File $path not found on server at /var/www/html";
    }
}

# Test 14: LDAP error disclosure
sub vulnerable_ldap_error {
    use Net::LDAP;
    my $ldap = Net::LDAP->new('ldap.example.com');
    my $mesg = $ldap->bind('cn=admin,dc=example,dc=com', password => 'wrong');
    if ($mesg->code) {
        print $cgi->header('text/html');
        # VULNERABLE: LDAP error disclosure
        print "LDAP Error: " . $mesg->error . "\n";
        print "Server: ldap.example.com\n";
    }
}

# Test 15: API key in error
sub vulnerable_api_key_error {
    my $response = call_api();
    unless ($response->{success}) {
        print $cgi->header('text/html');
        # VULNERABLE: API key in error message
        print "API call failed with key: sk_live_abc123xyz\n";
        print "Error: " . $response->{error};
    }
}

# Helper functions
sub get_user { return { id => 1, name => "test", password_hash => "abc123" }; }
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }
sub get_session { return { user_id => 1, token => "secret123", admin => 1 }; }
sub call_api { return { success => 0, error => "Timeout" }; }

1;
