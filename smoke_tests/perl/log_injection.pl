#!/usr/bin/perl
# Log Injection vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: warn() with user input
sub vulnerable_warn {
    my $username = $cgi->param('username');
    # VULNERABLE: Log injection via warn
    warn "Login attempt for user: $username";
}

# Test 2: die() with user input
sub vulnerable_die {
    my $file = $cgi->param('file');
    # VULNERABLE: Log injection via die
    die "Cannot open file: $file" unless -e $file;
}

# Test 3: Carp::carp with user input
sub vulnerable_carp {
    use Carp;
    my $action = $cgi->param('action');
    # VULNERABLE: Log injection via carp
    carp "Invalid action requested: $action";
}

# Test 4: Carp::croak with user input
sub vulnerable_croak {
    use Carp;
    my $input = $cgi->param('input');
    # VULNERABLE: Log injection via croak
    croak "Validation failed for input: $input" unless $input =~ /^\d+$/;
}

# Test 5: Carp::cluck with user input
sub vulnerable_cluck {
    use Carp;
    my $param = $cgi->param('param');
    # VULNERABLE: Log injection via cluck
    cluck "Suspicious parameter value: $param";
}

# Test 6: Carp::confess with user input
sub vulnerable_confess {
    use Carp;
    my $error = $cgi->param('error');
    # VULNERABLE: Log injection via confess
    confess "Fatal error: $error";
}

# Test 7: print to STDERR
sub vulnerable_stderr {
    my $message = $cgi->param('message');
    # VULNERABLE: Log injection via STDERR
    print STDERR "Error: $message\n";
}

# Test 8: syslog with user input
sub vulnerable_syslog {
    use Sys::Syslog qw(:standard :macros);
    my $username = $cgi->param('username');
    openlog('myapp', 'ndelay,pid', LOG_LOCAL0);
    # VULNERABLE: Log injection via syslog
    syslog(LOG_INFO, "User $username logged in");
    closelog();
}

# Test 9: Log::Log4perl
sub vulnerable_log4perl {
    use Log::Log4perl;
    my $logger = Log::Log4perl->get_logger();
    my $user_agent = $ENV{HTTP_USER_AGENT};
    # VULNERABLE: Log injection via Log4perl
    $logger->info("Request from: $user_agent");
}

# Test 10: Log::Dispatch
sub vulnerable_log_dispatch {
    use Log::Dispatch;
    my $log = Log::Dispatch->new(outputs => [['Screen', min_level => 'info']]);
    my $path = $cgi->param('path');
    # VULNERABLE: Log injection via Log::Dispatch
    $log->info("Accessing path: $path");
}

# Test 11: File logging with user input
sub vulnerable_file_log {
    my $action = $cgi->param('action');
    my $user = $cgi->param('user');
    open(my $fh, '>>', '/var/log/myapp.log') or die;
    # VULNERABLE: Log injection via file
    print $fh "[" . localtime() . "] User $user performed action: $action\n";
    close($fh);
}

# Test 12: Apache log via print
sub vulnerable_apache_log {
    my $referer = $ENV{HTTP_REFERER};
    # VULNERABLE: Log injection in Apache error log
    print STDERR "[error] Invalid referer: $referer\n";
}

# Test 13: Log newline injection
sub vulnerable_newline_injection {
    my $data = $cgi->param('data');
    # VULNERABLE: Newline injection to forge log entries
    warn "Received data: $data";
    # Attacker can inject: "data\n[INFO] Admin logged in successfully"
}

# Test 14: JSON in logs
sub vulnerable_json_log {
    use JSON;
    my $input = $cgi->param('input');
    my $log_entry = encode_json({
        timestamp => time(),
        message => "Processed input",
        # VULNERABLE: User input in JSON log
        user_data => $input
    });
    print STDERR "$log_entry\n";
}

# Test 15: Audit logging
sub vulnerable_audit_log {
    my $dbh = get_dbh();
    my $action = $cgi->param('action');
    my $user_id = $cgi->cookie('user_id');
    # VULNERABLE: Log injection in database audit log
    $dbh->do("INSERT INTO audit_log (user_id, action, timestamp) VALUES (?, ?, NOW())",
        undef, $user_id, $action);
}

# Helper functions
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }

1;
