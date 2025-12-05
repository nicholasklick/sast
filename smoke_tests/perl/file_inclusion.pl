#!/usr/bin/perl
# File Inclusion vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: require with user input
sub vulnerable_require {
    my $module = $cgi->param('module');
    # VULNERABLE: Local/Remote file inclusion
    require $module;
}

# Test 2: do with user input
sub vulnerable_do {
    my $file = $cgi->param('file');
    # VULNERABLE: Execute arbitrary Perl file
    do $file;
}

# Test 3: use with variable (eval'd)
sub vulnerable_use {
    my $module = $cgi->param('module');
    # VULNERABLE: Load arbitrary module
    eval "use $module";
}

# Test 4: require with path manipulation
sub vulnerable_require_path {
    my $plugin = $cgi->param('plugin');
    # VULNERABLE: Path traversal in require
    require "./plugins/$plugin.pm";
}

# Test 5: do with template path
sub vulnerable_do_template {
    my $template = $cgi->param('template');
    # VULNERABLE: Template file inclusion
    do "/var/www/templates/$template";
}

# Test 6: AUTOLOAD exploitation
sub AUTOLOAD {
    our $AUTOLOAD;
    my $method = $AUTOLOAD;
    $method =~ s/.*:://;
    my $file = $cgi->param('handler');
    # VULNERABLE: Dynamic file loading
    do "/var/www/handlers/$file.pl";
}

# Test 7: Plugin loading system
sub load_plugin {
    my $plugin_name = $cgi->param('plugin');
    my @plugin_dirs = ('/var/www/plugins', '/opt/plugins');
    for my $dir (@plugin_dirs) {
        my $path = "$dir/$plugin_name.pm";
        if (-e $path) {
            # VULNERABLE: Loading from multiple paths
            require $path;
            last;
        }
    }
}

# Test 8: eval require combination
sub vulnerable_eval_require {
    my $class = $cgi->param('class');
    # VULNERABLE: Dynamic class loading
    eval "require $class; $class->new()";
}

# Test 9: lib path manipulation
sub vulnerable_lib_path {
    my $lib_dir = $cgi->param('lib');
    # VULNERABLE: Adding user-controlled path to @INC
    unshift @INC, $lib_dir;
    require "SomeModule.pm";
}

# Test 10: Configuration file inclusion
sub vulnerable_config_include {
    my $config = $cgi->param('config');
    # VULNERABLE: Including arbitrary config
    do "/etc/myapp/$config.conf";
}

# Test 11: Language file inclusion
sub vulnerable_lang_include {
    my $lang = $cgi->param('lang');
    # VULNERABLE: Language file inclusion
    do "./locales/$lang.pl";
}

# Test 12: Theme/skin inclusion
sub vulnerable_theme_include {
    my $theme = $cgi->param('theme');
    # VULNERABLE: Theme file inclusion
    require "./themes/$theme/init.pm";
}

# Test 13: Hook/callback loading
sub vulnerable_hook_loading {
    my $hook = $cgi->param('hook');
    # VULNERABLE: Hook file inclusion
    if (-e "./hooks/$hook.pl") {
        do "./hooks/$hook.pl";
    }
}

# Test 14: SSI-like inclusion
sub vulnerable_ssi_include {
    my $include = $cgi->param('include');
    open(my $fh, '<', $include);
    my $content = do { local $/; <$fh> };
    close($fh);
    # VULNERABLE: Including and executing included code
    eval $content;
}

# Test 15: Module::Load with user input
sub vulnerable_module_load {
    use Module::Load;
    my $module = $cgi->param('module');
    # VULNERABLE: Dynamic module loading
    load $module;
    $module->import();
}

1;
