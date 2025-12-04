# Weak Cryptography vulnerabilities in Ruby
require 'digest'
require 'openssl'

class WeakCryptoVulnerabilities
  def hash_md5(input)
    # VULNERABLE: MD5 is cryptographically broken
    Digest::MD5.hexdigest(input)
  end

  def hash_sha1(input)
    # VULNERABLE: SHA1 is deprecated
    Digest::SHA1.hexdigest(input)
  end

  def encrypt_des(data, key)
    # VULNERABLE: DES is obsolete
    cipher = OpenSSL::Cipher.new('DES-ECB')
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end

  def weak_random
    # VULNERABLE: Non-cryptographic random
    rand(1000000)
  end

  def weak_token
    # VULNERABLE: Predictable token
    Time.now.to_i.to_s
  end

  def weak_session_id
    # VULNERABLE: Predictable session
    "session_#{rand(10000)}"
  end

  def ecb_encryption(data, key)
    # VULNERABLE: ECB mode
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end
end
