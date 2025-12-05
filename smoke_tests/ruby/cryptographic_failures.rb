# Cryptographic Failures in Ruby
require 'openssl'
require 'digest'
require 'base64'

class CryptoController < ApplicationController
  # Test 1: ECB mode
  def encrypt_ecb
    data = params[:data]
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt
    # VULNERABLE: ECB mode reveals patterns
    cipher.key = 'sixteen byte key'
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end

  # Test 2: Hardcoded encryption key
  def encrypt_with_key
    data = params[:data]
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    # VULNERABLE: Hardcoded key
    cipher.key = '0123456789abcdef'
    cipher.iv = cipher.random_iv
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end

  # Test 3: Static IV
  def encrypt_static_iv
    data = params[:data]
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    cipher.key = OpenSSL::Random.random_bytes(16)
    # VULNERABLE: Static IV
    cipher.iv = "\x00" * 16
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end

  # Test 4: DES usage
  def encrypt_des
    data = params[:data]
    # VULNERABLE: DES is weak
    cipher = OpenSSL::Cipher.new('DES-CBC')
    cipher.encrypt
    cipher.key = 'password'
    cipher.iv = cipher.random_iv
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end

  # Test 5: MD5 for integrity
  def hash_md5
    data = params[:data]
    # VULNERABLE: MD5 is broken
    hash = Digest::MD5.hexdigest(data)
    render plain: hash
  end

  # Test 6: SHA1 for security
  def hash_sha1
    data = params[:data]
    # VULNERABLE: SHA1 is deprecated
    hash = Digest::SHA1.hexdigest(data)
    render plain: hash
  end

  # Test 7: Small RSA key
  def generate_rsa
    # VULNERABLE: 1024-bit RSA is too weak
    key = OpenSSL::PKey::RSA.new(1024)
    render plain: key.public_key.to_pem
  end

  # Test 8: Weak PBKDF2 iterations
  def derive_key
    password = params[:password]
    salt = OpenSSL::Random.random_bytes(16)
    # VULNERABLE: Only 1000 iterations
    key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 1000, 32, 'sha256')
    render plain: Base64.encode64(key)
  end

  # Test 9: Static salt
  def hash_with_salt
    password = params[:password]
    # VULNERABLE: Static salt
    salt = 'constant_salt_value'
    hash = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 100_000, 32, 'sha256')
    render plain: Base64.encode64(hash)
  end

  # Test 10: No authenticated encryption
  def encrypt_no_auth
    data = params[:data]
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    cipher.key = OpenSSL::Random.random_bytes(16)
    cipher.iv = OpenSSL::Random.random_bytes(16)
    # VULNERABLE: No authentication (padding oracle possible)
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end

  # Test 11: rand for crypto
  def generate_weak_key
    # VULNERABLE: rand is not cryptographically secure
    key = (0...16).map { rand(256).chr }.join
    render plain: Base64.encode64(key)
  end

  # Test 12: Password as key directly
  def encrypt_with_password
    password = params[:password]
    data = params[:data]
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    # VULNERABLE: Password should go through KDF
    cipher.key = password.ljust(16, "\x00")[0..15]
    cipher.iv = OpenSSL::Random.random_bytes(16)
    encrypted = cipher.update(data) + cipher.final
    render plain: Base64.encode64(encrypted)
  end
end
