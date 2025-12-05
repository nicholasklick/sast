#!/usr/bin/perl
# XML External Entity (XXE) vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use XML::Simple;
use XML::LibXML;
use XML::Parser;

my $cgi = CGI->new();

# Test 1: XML::Simple with default settings
sub vulnerable_xml_simple {
    my $xml_data = $cgi->param('xml');
    # VULNERABLE: XML::Simple parses external entities by default
    my $data = XMLin($xml_data);
    return $data;
}

# Test 2: XML::LibXML without disabling entities
sub vulnerable_libxml {
    my $xml_data = $cgi->param('xml');
    my $parser = XML::LibXML->new();
    # VULNERABLE: External entities enabled
    my $doc = $parser->parse_string($xml_data);
    return $doc;
}

# Test 3: XML::Parser default config
sub vulnerable_xml_parser {
    my $xml_data = $cgi->param('xml');
    my $parser = XML::Parser->new();
    # VULNERABLE: Default parser allows entities
    my $result = $parser->parse($xml_data);
    return $result;
}

# Test 4: XML from file upload
sub vulnerable_file_upload {
    my $upload = $cgi->upload('xmlfile');
    my $xml_content = do { local $/; <$upload> };
    # VULNERABLE: Parsing uploaded XML
    my $data = XMLin($xml_content);
    return $data;
}

# Test 5: XML::LibXML load_xml
sub vulnerable_load_xml {
    my $xml_file = $cgi->param('file');
    my $parser = XML::LibXML->new();
    # VULNERABLE: Loading external XML file
    my $doc = $parser->load_xml(location => $xml_file);
    return $doc;
}

# Test 6: SOAP request parsing
sub vulnerable_soap {
    my $soap_request = $cgi->param('soap');
    # VULNERABLE: SOAP XML parsing
    my $parser = XML::LibXML->new();
    my $doc = $parser->parse_string($soap_request);
    my $xpc = XML::LibXML::XPathContext->new($doc);
    return $xpc->findnodes('//Body');
}

# Test 7: XML::Twig without entity protection
sub vulnerable_xml_twig {
    use XML::Twig;
    my $xml_data = $cgi->param('xml');
    my $twig = XML::Twig->new();
    # VULNERABLE: Default XML::Twig config
    $twig->parse($xml_data);
    return $twig;
}

# Test 8: XML::DOM parsing
sub vulnerable_xml_dom {
    use XML::DOM;
    my $xml_data = $cgi->param('xml');
    my $parser = XML::DOM::Parser->new();
    # VULNERABLE: DOM parser with entities
    my $doc = $parser->parse($xml_data);
    return $doc;
}

# Test 9: SVG file processing
sub vulnerable_svg_processing {
    my $svg_data = $cgi->param('svg');
    # VULNERABLE: SVG can contain XXE
    my $data = XMLin($svg_data);
    return $data;
}

# Test 10: RSS/Atom feed parsing
sub vulnerable_feed_parsing {
    use XML::Feed;
    my $feed_url = $cgi->param('feed_url');
    # VULNERABLE: Feed parsing with potential XXE
    my $feed = XML::Feed->parse(URI->new($feed_url));
    return $feed;
}

# Test 11: XPath with user input on parsed XML
sub vulnerable_xpath {
    my $xml_data = $cgi->param('xml');
    my $xpath = $cgi->param('xpath');
    my $parser = XML::LibXML->new();
    my $doc = $parser->parse_string($xml_data);
    # VULNERABLE: XXE in parsed document
    my @nodes = $doc->findnodes($xpath);
    return @nodes;
}

# Test 12: XSLT transformation
sub vulnerable_xslt {
    use XML::LibXSLT;
    my $xml_data = $cgi->param('xml');
    my $xslt_data = $cgi->param('xslt');
    my $parser = XML::LibXML->new();
    my $xslt = XML::LibXSLT->new();
    my $source = $parser->parse_string($xml_data);
    my $style_doc = $parser->parse_string($xslt_data);
    # VULNERABLE: XSLT with external entities
    my $stylesheet = $xslt->parse_stylesheet($style_doc);
    return $stylesheet->transform($source);
}

# Test 13: XML config file loading
sub vulnerable_config_loading {
    my $config_file = $cgi->param('config');
    # VULNERABLE: Loading config XML from user path
    my $config = XMLin($config_file);
    return $config;
}

# Test 14: Webhook XML payload
sub vulnerable_webhook {
    my $payload = $cgi->param('POSTDATA');
    if ($ENV{CONTENT_TYPE} =~ /xml/) {
        # VULNERABLE: Webhook XML parsing
        my $data = XMLin($payload);
        process_webhook($data);
    }
}

# Test 15: SAML response parsing
sub vulnerable_saml {
    my $saml_response = $cgi->param('SAMLResponse');
    use MIME::Base64;
    my $xml = decode_base64($saml_response);
    # VULNERABLE: SAML XXE
    my $parser = XML::LibXML->new();
    my $doc = $parser->parse_string($xml);
    return $doc;
}

# Helper functions
sub process_webhook { }

1;
