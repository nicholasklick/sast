#!/usr/bin/perl
# Code Injection vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: eval with user input
sub vulnerable_eval {
    my $code = $cgi->param('code');
    # VULNERABLE: Direct code injection
    my $result = eval($code);
    return $result;
}

# Test 2: eval with string interpolation
sub vulnerable_eval_interpolation {
    my $expr = $cgi->param('expr');
    # VULNERABLE: Code injection via interpolation
    my $result = eval "print $expr";
    return $result;
}

# Test 3: do FILE with user input
sub vulnerable_do_file {
    my $file = $cgi->param('file');
    # VULNERABLE: Arbitrary file execution
    do $file;
}

# Test 4: require with user input
sub vulnerable_require {
    my $module = $cgi->param('module');
    # VULNERABLE: Arbitrary module loading
    require $module;
}

# Test 5: use with variable (compile-time, but pattern is dangerous)
sub load_module {
    my $module = $cgi->param('module');
    # VULNERABLE: Dynamic module loading
    eval "use $module";
}

# Test 6: eval in regex replacement
sub vulnerable_eval_regex {
    my $input = $cgi->param('input');
    my $replace = $cgi->param('replace');
    # VULNERABLE: e modifier executes code
    $input =~ s/pattern/$replace/ee;
    return $input;
}

# Test 7: Symbolic reference
sub vulnerable_symbolic_ref {
    no strict 'refs';
    my $func_name = $cgi->param('func');
    # VULNERABLE: Arbitrary function call
    my $result = &{$func_name}();
    return $result;
}

# Test 8: Indirect object syntax
sub vulnerable_indirect_object {
    my $class = $cgi->param('class');
    my $method = $cgi->param('method');
    # VULNERABLE: Arbitrary method call
    my $obj = $class->new();
    $obj->$method();
}

# Test 9: AUTOLOAD exploitation
sub vulnerable_autoload {
    my $method = $cgi->param('method');
    # VULNERABLE: Dynamic method dispatch
    my $obj = MyClass->new();
    $obj->$method();
}

# Test 10: String eval for template
sub vulnerable_template_eval {
    my $template = $cgi->param('template');
    # VULNERABLE: Template code injection
    my $result = eval qq{qq{$template}};
    return $result;
}

# Test 11: Format string vulnerability
sub vulnerable_format {
    my $format_str = $cgi->param('format');
    # VULNERABLE: Format string attack
    eval "format = $format_str .";
}

# Test 12: Safe module bypass
sub vulnerable_safe_bypass {
    my $code = $cgi->param('code');
    # VULNERABLE: Even with Safe, shared variables can leak
    use Safe;
    my $compartment = Safe->new();
    $compartment->permit_only(qw(const padany));
    my $result = $compartment->reval($code);
    return $result;
}

# Test 13: BEGIN block (compile-time danger)
# This is a pattern to detect, not a runtime vulnerability
sub dangerous_begin_pattern {
    my $code = shift;
    # VULNERABLE: Compile-time code execution
    eval "BEGIN { $code }";
}

# Test 14: Regex code evaluation
sub vulnerable_regex_code {
    my $pattern = $cgi->param('pattern');
    my $text = "some text";
    # VULNERABLE: Regex with embedded code
    eval { $text =~ /(?{ $pattern })/ };
}

# Test 15: Method call via variable
sub vulnerable_method_variable {
    my $method = $cgi->param('method');
    my $obj = SomeClass->new();
    # VULNERABLE: Arbitrary method call
    my $result = $obj->$method();
    return $result;
}

1;
