#!/usr/bin/perl
# Server-Side Request Forgery (SSRF) vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Request;

my $cgi = CGI->new();

# Test 1: LWP::Simple get() with user URL
sub vulnerable_lwp_simple_get {
    my $url = $cgi->param('url');
    # VULNERABLE: SSRF via LWP::Simple
    my $content = get($url);
    return $content;
}

# Test 2: LWP::Simple getprint()
sub vulnerable_lwp_getprint {
    my $url = $cgi->param('url');
    # VULNERABLE: SSRF with direct output
    getprint($url);
}

# Test 3: LWP::Simple getstore()
sub vulnerable_lwp_getstore {
    my $url = $cgi->param('url');
    my $filename = $cgi->param('filename');
    # VULNERABLE: SSRF with file storage
    getstore($url, "/tmp/$filename");
}

# Test 4: LWP::UserAgent request()
sub vulnerable_lwp_ua_request {
    my $url = $cgi->param('url');
    my $ua = LWP::UserAgent->new();
    my $req = HTTP::Request->new(GET => $url);
    # VULNERABLE: SSRF via UserAgent
    my $response = $ua->request($req);
    return $response->decoded_content();
}

# Test 5: LWP::UserAgent get()
sub vulnerable_lwp_ua_get {
    my $url = $cgi->param('url');
    my $ua = LWP::UserAgent->new();
    # VULNERABLE: SSRF via UA get
    my $response = $ua->get($url);
    return $response->content();
}

# Test 6: HTTP::Tiny
sub vulnerable_http_tiny {
    use HTTP::Tiny;
    my $url = $cgi->param('url');
    my $http = HTTP::Tiny->new();
    # VULNERABLE: SSRF via HTTP::Tiny
    my $response = $http->get($url);
    return $response->{content};
}

# Test 7: IO::Socket::INET
sub vulnerable_socket {
    use IO::Socket::INET;
    my $host = $cgi->param('host');
    my $port = $cgi->param('port');
    # VULNERABLE: SSRF via raw socket
    my $socket = IO::Socket::INET->new(
        PeerHost => $host,
        PeerPort => $port,
        Proto    => 'tcp'
    );
    return $socket;
}

# Test 8: Net::HTTP
sub vulnerable_net_http {
    use Net::HTTP;
    my $host = $cgi->param('host');
    # VULNERABLE: SSRF via Net::HTTP
    my $s = Net::HTTP->new(Host => $host);
    $s->write_request(GET => '/');
    return $s->read_response_headers();
}

# Test 9: URL from header
sub vulnerable_header_ssrf {
    my $callback_url = $ENV{HTTP_X_CALLBACK_URL};
    my $ua = LWP::UserAgent->new();
    # VULNERABLE: SSRF via header
    my $response = $ua->get($callback_url);
    return $response;
}

# Test 10: URL from referer
sub vulnerable_referer_ssrf {
    my $referer = $ENV{HTTP_REFERER};
    my $ua = LWP::UserAgent->new();
    # VULNERABLE: SSRF via referer
    my $response = $ua->head($referer);
    return $response;
}

# Test 11: Webhook URL
sub vulnerable_webhook {
    my $webhook_url = $cgi->param('webhook');
    my $ua = LWP::UserAgent->new();
    my $data = '{"event":"test"}';
    # VULNERABLE: SSRF via webhook
    my $response = $ua->post($webhook_url, Content => $data);
    return $response;
}

# Test 12: Image/file fetch
sub vulnerable_image_fetch {
    my $image_url = $cgi->param('image_url');
    # VULNERABLE: SSRF via image fetch
    my $image_data = get($image_url);
    return $image_data;
}

# Test 13: API proxy
sub vulnerable_api_proxy {
    my $api_endpoint = $cgi->param('endpoint');
    my $ua = LWP::UserAgent->new();
    # VULNERABLE: API proxy SSRF
    my $response = $ua->get("http://internal-api.local/$api_endpoint");
    return $response->decoded_content();
}

# Test 14: URL with user-controlled port
sub vulnerable_port_scan {
    my $host = $cgi->param('host');
    my $port = $cgi->param('port');
    # VULNERABLE: Port scanning via SSRF
    my $url = "http://$host:$port/";
    my $content = get($url);
    return defined($content) ? "Open" : "Closed";
}

# Test 15: DNS rebinding vector
sub vulnerable_dns_rebind {
    my $domain = $cgi->param('domain');
    my $ua = LWP::UserAgent->new();
    # VULNERABLE: DNS rebinding attack vector
    my $response = $ua->get("http://$domain/api/internal");
    return $response;
}

1;
