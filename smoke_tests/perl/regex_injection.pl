#!/usr/bin/perl
# Regex Injection / ReDoS vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: User-controlled pattern in match
sub vulnerable_match {
    my $pattern = $cgi->param('pattern');
    my $text = "some text to search";
    # VULNERABLE: Regex injection
    if ($text =~ /$pattern/) {
        return "Match found";
    }
    return "No match";
}

# Test 2: User-controlled pattern in substitution
sub vulnerable_substitution {
    my $pattern = $cgi->param('pattern');
    my $replacement = $cgi->param('replacement');
    my $text = $cgi->param('text');
    # VULNERABLE: Regex injection in s///
    $text =~ s/$pattern/$replacement/g;
    return $text;
}

# Test 3: ReDoS with nested quantifiers
sub vulnerable_redos_nested {
    my $input = $cgi->param('input');
    # VULNERABLE: Evil regex - nested quantifiers
    if ($input =~ /^(a+)+$/) {
        return "Valid";
    }
    return "Invalid";
}

# Test 4: ReDoS with alternation
sub vulnerable_redos_alternation {
    my $email = $cgi->param('email');
    # VULNERABLE: ReDoS prone email regex
    if ($email =~ /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$/) {
        return "Valid email";
    }
    return "Invalid email";
}

# Test 5: User pattern with qr//
sub vulnerable_qr {
    my $pattern = $cgi->param('pattern');
    # VULNERABLE: Compiling user pattern
    my $regex = qr/$pattern/;
    my $text = "test string";
    if ($text =~ $regex) {
        return "Matched";
    }
    return "Not matched";
}

# Test 6: grep with user pattern
sub vulnerable_grep {
    my $pattern = $cgi->param('pattern');
    my @lines = ("line1", "line2", "line3");
    # VULNERABLE: grep with user pattern
    my @matches = grep { /$pattern/ } @lines;
    return @matches;
}

# Test 7: split with user pattern
sub vulnerable_split {
    my $delimiter = $cgi->param('delimiter');
    my $text = $cgi->param('text');
    # VULNERABLE: split with user delimiter
    my @parts = split(/$delimiter/, $text);
    return @parts;
}

# Test 8: Regex code execution with (?{})
sub vulnerable_regex_code_exec {
    my $pattern = $cgi->param('pattern');
    my $text = "test";
    # VULNERABLE: Code execution in regex
    eval { $text =~ /(?{$pattern})/ };
}

# Test 9: eval with regex replacement (e modifier)
sub vulnerable_eval_replacement {
    my $text = $cgi->param('text');
    my $expr = $cgi->param('expr');
    # VULNERABLE: e modifier evaluates replacement as code
    $text =~ s/(\w+)/$expr/ee;
    return $text;
}

# Test 10: Case-insensitive pattern injection
sub vulnerable_case_insensitive {
    my $search = $cgi->param('search');
    my $text = "The Quick Brown Fox";
    # VULNERABLE: Pattern injection with modifiers
    if ($text =~ /$search/i) {
        return "Found";
    }
    return "Not found";
}

# Test 11: ReDoS in URL validation
sub vulnerable_url_regex {
    my $url = $cgi->param('url');
    # VULNERABLE: ReDoS in URL regex
    if ($url =~ /^https?:\/\/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)*$/) {
        return "Valid URL";
    }
    return "Invalid URL";
}

# Test 12: Complex ReDoS pattern
sub vulnerable_complex_redos {
    my $data = $cgi->param('data');
    # VULNERABLE: Multiple overlapping groups
    if ($data =~ /^([a-z]+)*([A-Z]+)*([0-9]+)*$/) {
        return "Matched";
    }
    return "Not matched";
}

# Test 13: Backreference with user input
sub vulnerable_backreference {
    my $pattern = $cgi->param('pattern');
    my $text = "abab cdcd";
    # VULNERABLE: Backreference can cause ReDoS
    if ($text =~ /$pattern/) {
        return "Match";
    }
    return "No match";
}

# Test 14: Locale-based regex issue
sub vulnerable_locale {
    use locale;
    my $pattern = $cgi->param('pattern');
    my $text = "Résumé";
    # VULNERABLE: Locale-dependent regex
    if ($text =~ /$pattern/i) {
        return "Match";
    }
    return "No match";
}

# Test 15: tr/// with user characters
sub vulnerable_tr {
    my $from = $cgi->param('from');
    my $to = $cgi->param('to');
    my $text = $cgi->param('text');
    # VULNERABLE: User-controlled transliteration
    eval "\$text =~ tr/$from/$to/";
    return $text;
}

1;
