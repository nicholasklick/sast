#!/usr/bin/perl
# Insecure Deserialization vulnerabilities in Perl

use strict;
use warnings;
use CGI;
use Storable;
use YAML;
use JSON;
use Data::Dumper;

my $cgi = CGI->new();

# Test 1: Storable thaw() with user input
sub vulnerable_storable_thaw {
    my $data = $cgi->param('data');
    # VULNERABLE: Arbitrary code execution via Storable
    my $obj = Storable::thaw($data);
    return $obj;
}

# Test 2: Storable retrieve() with user path
sub vulnerable_storable_retrieve {
    my $file = $cgi->param('file');
    # VULNERABLE: Deserialize from user-controlled path
    my $obj = Storable::retrieve($file);
    return $obj;
}

# Test 3: Storable fd_retrieve()
sub vulnerable_storable_fd {
    my $fd_num = $cgi->param('fd');
    # VULNERABLE: Deserialize from file descriptor
    open(my $fh, "<&=$fd_num") or die;
    my $obj = Storable::fd_retrieve($fh);
    close($fh);
    return $obj;
}

# Test 4: YAML::Load with user input
sub vulnerable_yaml_load {
    my $yaml_data = $cgi->param('yaml');
    # VULNERABLE: YAML deserialization (code execution possible)
    my $data = YAML::Load($yaml_data);
    return $data;
}

# Test 5: YAML::LoadFile with user path
sub vulnerable_yaml_loadfile {
    my $file = $cgi->param('file');
    # VULNERABLE: YAML from user-controlled file
    my $data = YAML::LoadFile($file);
    return $data;
}

# Test 6: YAML::XS Load (also vulnerable)
sub vulnerable_yaml_xs {
    use YAML::XS;
    my $yaml_data = $cgi->param('yaml');
    # VULNERABLE: YAML::XS deserialization
    my $data = YAML::XS::Load($yaml_data);
    return $data;
}

# Test 7: JSON decode with object hooks
sub vulnerable_json_decode {
    my $json_data = $cgi->param('json');
    my $json = JSON->new->allow_blessed->convert_blessed;
    # VULNERABLE: JSON with blessed objects
    my $data = $json->decode($json_data);
    return $data;
}

# Test 8: decode_json function
sub vulnerable_decode_json {
    my $json_data = $cgi->param('json');
    # VULNERABLE if JSON contains blessed references
    my $data = decode_json($json_data);
    return $data;
}

# Test 9: Data::Serializer
sub vulnerable_data_serializer {
    use Data::Serializer;
    my $serialized = $cgi->param('data');
    my $serializer = Data::Serializer->new();
    # VULNERABLE: Arbitrary deserialization
    my $data = $serializer->deserialize($serialized);
    return $data;
}

# Test 10: PHP::Serialization
sub vulnerable_php_serialization {
    use PHP::Serialization;
    my $php_data = $cgi->param('php_data');
    # VULNERABLE: PHP serialized data
    my $data = PHP::Serialization::unserialize($php_data);
    return $data;
}

# Test 11: Sereal decoder
sub vulnerable_sereal {
    use Sereal::Decoder;
    my $sereal_data = $cgi->param('sereal');
    my $decoder = Sereal::Decoder->new();
    # VULNERABLE: Sereal deserialization
    my $data = $decoder->decode($sereal_data);
    return $data;
}

# Test 12: XML::Simple XMLin
sub vulnerable_xml_simple {
    use XML::Simple;
    my $xml_data = $cgi->param('xml');
    # VULNERABLE: XML deserialization (XXE + code execution)
    my $data = XMLin($xml_data);
    return $data;
}

# Test 13: Cookie deserialization
sub vulnerable_cookie_deserialize {
    my $session_cookie = $cgi->cookie('session');
    # VULNERABLE: Session deserialization
    my $session = Storable::thaw(decode_base64($session_cookie));
    return $session;
}

# Test 14: Message queue deserialization
sub vulnerable_mq_deserialize {
    my $message = get_message_from_queue();
    # VULNERABLE: Deserialize untrusted message
    my $data = Storable::thaw($message);
    process_message($data);
}

# Test 15: Database blob deserialization
sub vulnerable_db_deserialize {
    my $id = $cgi->param('id');
    my $dbh = get_dbh();
    my $sth = $dbh->prepare("SELECT serialized_data FROM objects WHERE id = ?");
    $sth->execute($id);
    my ($serialized) = $sth->fetchrow_array();
    # VULNERABLE: Deserialize data from database
    my $obj = Storable::thaw($serialized);
    return $obj;
}

# Helper functions
sub get_message_from_queue { return ""; }
sub process_message { }
sub get_dbh { return DBI->connect("dbi:SQLite:dbname=test.db"); }
sub decode_base64 { use MIME::Base64; return MIME::Base64::decode_base64(shift); }

1;
