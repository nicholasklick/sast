#!/usr/bin/perl
# Path Traversal vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use File::Spec;

my $cgi = CGI->new();

# Test 1: open() with user input
sub vulnerable_open {
    my $filename = $cgi->param('file');
    # VULNERABLE: Path traversal via open
    open(my $fh, '<', $filename) or die "Cannot open: $!";
    my @content = <$fh>;
    close($fh);
    return @content;
}

# Test 2: sysopen with user input
sub vulnerable_sysopen {
    my $file = $cgi->param('file');
    # VULNERABLE: Path traversal via sysopen
    sysopen(my $fh, $file, O_RDONLY) or die "Cannot open: $!";
    my $content;
    sysread($fh, $content, 1024);
    close($fh);
    return $content;
}

# Test 3: open for writing
sub vulnerable_open_write {
    my $filename = $cgi->param('filename');
    my $content = $cgi->param('content');
    # VULNERABLE: Arbitrary file write
    open(my $fh, '>', "/var/www/uploads/$filename") or die "Cannot write: $!";
    print $fh $content;
    close($fh);
}

# Test 4: unlink with user input
sub vulnerable_unlink {
    my $file = $cgi->param('file');
    # VULNERABLE: Arbitrary file deletion
    unlink("/var/www/uploads/$file");
}

# Test 5: rename with user input
sub vulnerable_rename {
    my $old = $cgi->param('old');
    my $new = $cgi->param('new');
    # VULNERABLE: Path traversal in rename
    rename("/var/www/files/$old", "/var/www/files/$new");
}

# Test 6: symlink creation
sub vulnerable_symlink {
    my $target = $cgi->param('target');
    my $link = $cgi->param('link');
    # VULNERABLE: Symlink attack
    symlink($target, "/var/www/files/$link");
}

# Test 7: mkdir with user input
sub vulnerable_mkdir {
    my $dir = $cgi->param('dir');
    # VULNERABLE: Directory traversal
    mkdir("/var/www/data/$dir", 0755);
}

# Test 8: rmdir with user input
sub vulnerable_rmdir {
    my $dir = $cgi->param('dir');
    # VULNERABLE: Directory traversal in delete
    rmdir("/var/www/data/$dir");
}

# Test 9: chmod with user input
sub vulnerable_chmod {
    my $file = $cgi->param('file');
    my $mode = $cgi->param('mode');
    # VULNERABLE: Arbitrary file permission change
    chmod(oct($mode), "/var/www/files/$file");
}

# Test 10: chown with user input
sub vulnerable_chown {
    my $file = $cgi->param('file');
    my $uid = $cgi->param('uid');
    my $gid = $cgi->param('gid');
    # VULNERABLE: Arbitrary file ownership change
    chown($uid, $gid, "/var/www/files/$file");
}

# Test 11: Link creation
sub vulnerable_link {
    my $source = $cgi->param('source');
    my $dest = $cgi->param('dest');
    # VULNERABLE: Hard link creation
    link("/var/www/files/$source", "/var/www/files/$dest");
}

# Test 12: truncate with user input
sub vulnerable_truncate {
    my $file = $cgi->param('file');
    # VULNERABLE: File truncation
    truncate("/var/www/files/$file", 0);
}

# Test 13: File::Slurp read
sub vulnerable_file_slurp {
    use File::Slurp;
    my $file = $cgi->param('file');
    # VULNERABLE: Path traversal
    my $content = read_file($file);
    return $content;
}

# Test 14: readdir abuse
sub vulnerable_readdir {
    my $dir = $cgi->param('dir');
    # VULNERABLE: Directory listing outside intended path
    opendir(my $dh, $dir) or die "Cannot open directory: $!";
    my @files = readdir($dh);
    closedir($dh);
    return @files;
}

# Test 15: File::Copy operations
sub vulnerable_file_copy {
    use File::Copy;
    my $source = $cgi->param('source');
    my $dest = $cgi->param('dest');
    # VULNERABLE: Path traversal in copy
    copy("/var/www/files/$source", "/var/www/backup/$dest");
}

1;
