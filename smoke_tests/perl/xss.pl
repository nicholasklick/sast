#!/usr/bin/perl
# Cross-Site Scripting (XSS) vulnerabilities in Perl CGI

use strict;
use warnings;
use CGI;

my $cgi = CGI->new();

# Test 1: Direct print of user input
sub vulnerable_print {
    my $name = $cgi->param('name');
    print "Content-Type: text/html\n\n";
    # VULNERABLE: Reflected XSS
    print "<h1>Hello, $name!</h1>";
}

# Test 2: say with user input
sub vulnerable_say {
    my $message = $cgi->param('message');
    print "Content-Type: text/html\n\n";
    # VULNERABLE: XSS via say
    say "<div>$message</div>";
}

# Test 3: printf with user input
sub vulnerable_printf {
    my $username = $cgi->param('username');
    print "Content-Type: text/html\n\n";
    # VULNERABLE: XSS via printf
    printf("<span class='user'>%s</span>", $username);
}

# Test 4: CGI start_html with user input
sub vulnerable_start_html {
    my $title = $cgi->param('title');
    # VULNERABLE: XSS in page title
    print $cgi->header();
    print $cgi->start_html(-title => $title);
    print $cgi->end_html();
}

# Test 5: CGI hidden field
sub vulnerable_hidden_field {
    my $value = $cgi->param('value');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: XSS in hidden field
    print $cgi->hidden(-name => 'data', -value => $value);
    print $cgi->end_html();
}

# Test 6: CGI textfield
sub vulnerable_textfield {
    my $default = $cgi->param('default');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: XSS in form field default
    print $cgi->textfield(-name => 'input', -default => $default);
    print $cgi->end_html();
}

# Test 7: HTML::Template with unescaped variable
sub vulnerable_html_template {
    use HTML::Template;
    my $name = $cgi->param('name');
    my $template = HTML::Template->new(filename => 'template.tmpl');
    # VULNERABLE: Template variable not escaped
    $template->param(NAME => $name);
    print $cgi->header();
    print $template->output();
}

# Test 8: Template Toolkit without AUTO_FILTER
sub vulnerable_template_toolkit {
    use Template;
    my $comment = $cgi->param('comment');
    my $tt = Template->new();
    # VULNERABLE: No auto-escaping
    $tt->process('page.tt', { comment => $comment });
}

# Test 9: Here-doc with interpolation
sub vulnerable_heredoc {
    my $content = $cgi->param('content');
    print "Content-Type: text/html\n\n";
    # VULNERABLE: XSS via here-doc
    print <<"HTML";
<html>
<body>
<div class="content">$content</div>
</body>
</html>
HTML
}

# Test 10: JSON output with user data
sub vulnerable_json_output {
    my $callback = $cgi->param('callback');
    my $data = '{"status":"ok"}';
    print "Content-Type: application/javascript\n\n";
    # VULNERABLE: JSONP callback injection
    print "$callback($data)";
}

# Test 11: Error message reflection
sub vulnerable_error_message {
    my $input = $cgi->param('input');
    if (!$input) {
        print $cgi->header();
        print $cgi->start_html();
        # VULNERABLE: Error message XSS
        print "<p class='error'>Invalid input: $input</p>";
        print $cgi->end_html();
    }
}

# Test 12: URL parameter in link
sub vulnerable_link {
    my $url = $cgi->param('url');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: XSS via javascript: URL
    print "<a href='$url'>Click here</a>";
    print $cgi->end_html();
}

# Test 13: Event handler injection
sub vulnerable_event_handler {
    my $action = $cgi->param('action');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: Event handler XSS
    print "<button onclick='$action'>Submit</button>";
    print $cgi->end_html();
}

# Test 14: Style attribute injection
sub vulnerable_style {
    my $color = $cgi->param('color');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: CSS injection
    print "<div style='background-color: $color'>Content</div>";
    print $cgi->end_html();
}

# Test 15: Cookie value reflection
sub vulnerable_cookie_reflection {
    my $cookie_value = $cgi->cookie('user_pref');
    print $cgi->header();
    print $cgi->start_html();
    # VULNERABLE: Cookie-based XSS
    print "<div>Your preference: $cookie_value</div>";
    print $cgi->end_html();
}

1;
