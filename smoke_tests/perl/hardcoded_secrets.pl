#!/usr/bin/perl
# Hardcoded Secrets vulnerabilities in Perl

use strict;
use warnings;

# Test 1: Hardcoded password
my $password = "SuperSecretP@ssw0rd123!";

# Test 2: Hardcoded API key
my $api_key = "sk_live_abcdef1234567890abcdef1234567890";

# Test 3: Hardcoded AWS credentials
my $aws_access_key = "AKIAIOSFODNN7EXAMPLE";
my $aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

# Test 4: Hardcoded database credentials
sub get_db_connection {
    use DBI;
    # VULNERABLE: Hardcoded credentials
    my $dbh = DBI->connect(
        "dbi:mysql:database=production",
        "admin",
        "db_password_123"
    );
    return $dbh;
}

# Test 5: Hardcoded JWT secret
my $jwt_secret = "your-256-bit-secret-key-here-for-jwt-tokens";

# Test 6: Hardcoded encryption key
my $encryption_key = "0123456789abcdef0123456789abcdef";
my $aes_iv = "fedcba9876543210";

# Test 7: Hardcoded OAuth credentials
my $client_id = "1234567890-abcdefghijklmnop.apps.googleusercontent.com";
my $client_secret = "GOCSPX-abcdefghijklmnopqrstuvwxyz";

# Test 8: Hardcoded SSH private key
my $ssh_private_key = <<'END_KEY';
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MmVsLJ8xyV1PxQ4T
... (truncated for security)
-----END RSA PRIVATE KEY-----
END_KEY

# Test 9: Hardcoded token in config hash
my %config = (
    api_endpoint => "https://api.example.com",
    auth_token => "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    secret_key => "super_secret_value_12345",
);

# Test 10: Hardcoded SMTP credentials
my $smtp_user = "noreply@example.com";
my $smtp_pass = "smtp_password_secret";

# Test 11: Hardcoded Stripe key
my $stripe_secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

# Test 12: Hardcoded Twilio credentials
my $twilio_sid = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
my $twilio_auth = "your_auth_token_here";

# Test 13: Hardcoded GitHub token
my $github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

# Test 14: Hardcoded Slack webhook
my $slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

# Test 15: Hardcoded private key in connect string
sub connect_to_api {
    use LWP::UserAgent;
    my $ua = LWP::UserAgent->new();
    $ua->default_header('X-API-Key' => 'private_key_abc123xyz789');
    return $ua;
}

# Test 16: Password in environment setup
$ENV{DB_PASSWORD} = "hardcoded_env_password";

# Test 17: Credentials in regex (for matching, but still exposed)
sub validate_key {
    my $key = shift;
    # VULNERABLE: Exposes valid key pattern with example
    if ($key =~ /^sk_live_[a-zA-Z0-9]{32}$/) {
        return 1;
    }
    return 0;
}

# Test 18: Base64 encoded password (still a secret)
my $encoded_password = "U3VwZXJTZWNyZXRQYXNzd29yZA==";

1;
