#!/bin/bash
# Hardcoded Secrets vulnerabilities in Bash

# Test 1: Hardcoded password
PASSWORD="SuperSecretP@ssw0rd123!"

# Test 2: Hardcoded API key
API_KEY="sk_live_abcdef1234567890abcdef1234567890"

# Test 3: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Test 4: Database credentials
DB_USER="admin"
DB_PASS="db_password_123"

# Test 5: MySQL connection with embedded password
mysql_connect() {
    # VULNERABLE: Password in command line
    mysql -u admin -pSecretPassword123 -h localhost database
}

# Test 6: curl with embedded credentials
curl_auth() {
    # VULNERABLE: Credentials in URL
    curl "https://admin:password123@api.example.com/data"
}

# Test 7: SSH with embedded password (sshpass)
ssh_connect() {
    # VULNERABLE: Password in command
    sshpass -p 'MySSHPassword' ssh user@server.com
}

# Test 8: Private key inline
SSH_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----"

# Test 9: Bearer token
AUTH_TOKEN="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# Test 10: Slack webhook URL
SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Test 11: GitHub token
GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Test 12: Stripe key
STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"

# Test 13: SendGrid API key
SENDGRID_API_KEY="SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Test 14: Docker registry credentials
DOCKER_PASSWORD="docker_registry_password"

# Test 15: Encryption key
ENCRYPTION_KEY="0123456789abcdef0123456789abcdef"

# Test 16: Basic auth header
AUTH_HEADER="Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM="

# Test 17: OAuth client secret
OAUTH_CLIENT_SECRET="GOCSPX-abcdefghijklmnopqrstuvwxyz"

# Test 18: Twilio credentials
TWILIO_AUTH_TOKEN="your_auth_token_here"
TWILIO_ACCOUNT_SID="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Test 19: Firebase credentials
FIREBASE_API_KEY="AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Test 20: Password in export
export DB_PASSWORD="exported_password"
