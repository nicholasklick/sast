#!/usr/bin/perl -T
# Perl Taint Mode bypass and abuse vulnerabilities
# Note: This file should be run with -T flag for taint mode

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: Bypassing taint mode with regex
sub vulnerable_taint_bypass_regex {
    my $tainted_input = $cgi->param('input');
    # VULNERABLE: Weak regex untainting
    if ($tainted_input =~ /(.*)/) {
        my $untainted = $1;
        system($untainted);  # Still dangerous!
    }
}

# Test 2: Untainting with overly permissive pattern
sub vulnerable_weak_untaint {
    my $filename = $cgi->param('file');
    # VULNERABLE: Pattern matches almost anything
    if ($filename =~ /^(.+)$/) {
        my $clean = $1;
        open(my $fh, '<', $clean);
    }
}

# Test 3: Environment PATH not cleaned
sub vulnerable_path_not_set {
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: PATH not cleaned in taint mode
    delete $ENV{PATH};  # Should set explicitly
    system($cmd);
}

# Test 4: IFS not cleaned
sub vulnerable_ifs_not_set {
    delete $ENV{IFS};  # Not sufficient
    # VULNERABLE: IFS manipulation possible
    my $file = $cgi->param('file');
    if ($file =~ /^(\w+)$/) {
        system("cat", $1);
    }
}

# Test 5: Two-arg open with tainted data
sub vulnerable_two_arg_open {
    my $file = $cgi->param('file');
    if ($file =~ /^(\w+\.txt)$/) {
        my $clean = $1;
        # VULNERABLE: Two-arg open can still be exploited
        open(FH, $clean);
    }
}

# Test 6: Tainted data in backticks
sub vulnerable_tainted_backticks {
    my $host = $cgi->param('host');
    if ($host =~ /^([\w.]+)$/) {
        my $clean = $1;
        # VULNERABLE: Backticks with untainted but user data
        my $output = `ping -c 1 $clean`;
        return $output;
    }
}

# Test 7: Hash key from tainted data
sub vulnerable_hash_key_tainted {
    my $key = $cgi->param('key');
    my %dispatch = (
        'list'   => \&do_list,
        'delete' => \&do_delete,
    );
    # VULNERABLE: Using tainted key directly
    if (exists $dispatch{$key}) {
        $dispatch{$key}->();
    }
}

# Test 8: Symbolic reference with tainted data
sub vulnerable_symref_tainted {
    no strict 'refs';
    my $func = $cgi->param('func');
    if ($func =~ /^(\w+)$/) {
        my $clean = $1;
        # VULNERABLE: Calling arbitrary function
        &{$clean}();
    }
}

# Test 9: Module loading with user data
sub vulnerable_module_load {
    my $module = $cgi->param('module');
    if ($module =~ /^([\w:]+)$/) {
        my $clean = $1;
        # VULNERABLE: Loading arbitrary modules
        eval "require $clean";
    }
}

# Test 10: Database query with "clean" data
sub vulnerable_db_untainted {
    my $id = $cgi->param('id');
    if ($id =~ /^(\d+)$/) {
        my $clean = $1;
        my $dbh = get_dbh();
        # Still potentially vulnerable even if untainted
        $dbh->do("DELETE FROM logs WHERE id = $clean");
    }
}

# Test 11: File path construction
sub vulnerable_path_construction {
    my $dir = $cgi->param('dir');
    my $file = $cgi->param('file');
    if ($dir =~ /^(\w+)$/ && $file =~ /^(\w+\.txt)$/) {
        my ($clean_dir, $clean_file) = ($1, $2);
        # VULNERABLE: Path traversal still possible via intermediate steps
        my $path = "/var/www/$clean_dir/$clean_file";
        open(my $fh, '<', $path);
    }
}

# Test 12: Regex pattern from user
sub vulnerable_regex_from_user {
    my $pattern = $cgi->param('pattern');
    my $text = "some text";
    # VULNERABLE: ReDoS even in taint mode
    if ($text =~ /$pattern/) {
        return "Match";
    }
}

# Test 13: Cookie manipulation
sub vulnerable_cookie_taint {
    my $pref = $cgi->cookie('user_pref');
    if ($pref =~ /^([\w=]+)$/) {
        my $clean = $1;
        # VULNERABLE: Cookie data used unsafely
        eval "my \%hash = ($clean)";
    }
}

# Test 14: HTTP header injection
sub vulnerable_header_injection {
    my $location = $cgi->param('location');
    if ($location =~ m{^(https?://[\w./]+)$}) {
        my $clean = $1;
        # VULNERABLE: Header injection possible with CRLF
        print "Location: $clean\n\n";
    }
}

# Test 15: LDAP filter from untainted data
sub vulnerable_ldap_untainted {
    my $user = $cgi->param('user');
    if ($user =~ /^(\w+)$/) {
        my $clean = $1;
        use Net::LDAP;
        my $ldap = Net::LDAP->new('ldap://localhost');
        # VULNERABLE: LDAP injection even with basic untainting
        $ldap->search(filter => "(uid=$clean)");
    }
}

# Helper functions
sub do_list { print "List\n"; }
sub do_delete { print "Delete\n"; }
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }

1;
