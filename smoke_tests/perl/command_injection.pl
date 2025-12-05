#!/usr/bin/perl
# Command Injection vulnerabilities in Perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: system() with user input
sub run_command_system {
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: Direct command injection
    system($cmd);
}

# Test 2: exec() with user input
sub run_command_exec {
    my $program = $cgi->param('program');
    # VULNERABLE: exec with user input
    exec($program);
}

# Test 3: Backticks with user input
sub run_command_backticks {
    my $file = $cgi->param('file');
    # VULNERABLE: Backticks command injection
    my $output = `cat $file`;
    print $output;
}

# Test 4: qx// with user input
sub run_command_qx {
    my $pattern = $cgi->param('pattern');
    # VULNERABLE: qx operator
    my $result = qx(grep $pattern /var/log/messages);
    return $result;
}

# Test 5: open() with pipe
sub run_command_pipe {
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: Pipe open
    open(my $fh, "$cmd |") or die "Cannot run command: $!";
    while (<$fh>) {
        print;
    }
    close($fh);
}

# Test 6: Two-argument open with pipe
sub run_command_two_arg_open {
    my $file = $cgi->param('file');
    # VULNERABLE: Two-argument open with pipe
    open(PIPE, "cat $file |");
    my @lines = <PIPE>;
    close(PIPE);
    return @lines;
}

# Test 7: IPC::Open2
sub run_command_open2 {
    use IPC::Open2;
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: IPC::Open2
    my $pid = open2(\*READER, \*WRITER, $cmd);
    print WRITER "input\n";
    my $output = <READER>;
    return $output;
}

# Test 8: IPC::Open3
sub run_command_open3 {
    use IPC::Open3;
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: IPC::Open3
    my $pid = open3(\*WRITER, \*READER, \*ERROR, $cmd);
    my $output = <READER>;
    return $output;
}

# Test 9: readpipe
sub run_command_readpipe {
    my $cmd = $cgi->param('cmd');
    # VULNERABLE: readpipe function
    my $output = readpipe($cmd);
    return $output;
}

# Test 10: system with list form (safer but still potentially vulnerable)
sub run_command_system_list {
    my $file = $cgi->param('file');
    # VULNERABLE: Even list form can be dangerous with user input
    system("cat", $file);
}

# Test 11: Chained commands
sub run_chained_commands {
    my $name = $cgi->param('name');
    # VULNERABLE: Command chaining possible
    system("echo Hello $name && ls -la");
}

# Test 12: Environment manipulation
sub run_with_env {
    my $path = $cgi->param('path');
    # VULNERABLE: PATH manipulation
    $ENV{PATH} = $path;
    system("ls");
}

1;
