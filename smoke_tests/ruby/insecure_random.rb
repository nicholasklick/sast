# Insecure Randomness vulnerabilities in Ruby
class RandomController < ApplicationController
  # Test 1: rand for security token
  def generate_token
    # VULNERABLE: rand is not cryptographically secure
    token = (0...32).map { rand(36).to_s(36) }.join
    render plain: token
  end

  # Test 2: Random.rand for session
  def create_session
    # VULNERABLE: Kernel.rand is predictable
    session_id = rand.to_s[2..33]
    render plain: session_id
  end

  # Test 3: srand with predictable seed
  def seeded_random
    # VULNERABLE: Predictable seed
    srand(42)
    token = rand.to_s
    render plain: token
  end

  # Test 4: Time-based seed
  def time_seeded
    # VULNERABLE: Time-based seed is predictable
    srand(Time.now.to_i)
    render plain: rand.to_s
  end

  # Test 5: Array#sample for password
  def generate_password
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    # VULNERABLE: sample uses rand internally
    password = (0...12).map { chars.sample }.join
    render plain: password
  end

  # Test 6: Array#shuffle for security
  def shuffle_deck
    deck = (1..52).to_a
    # VULNERABLE: shuffle uses rand
    shuffled = deck.shuffle
    render json: shuffled
  end

  # Test 7: rand for CSRF token
  def get_csrf_token
    # VULNERABLE: CSRF token needs crypto random
    token = '%032x' % rand(2**128)
    render plain: token
  end

  # Test 8: rand for OTP
  def generate_otp
    # VULNERABLE: OTP should use SecureRandom
    otp = '%06d' % rand(1_000_000)
    render plain: otp
  end

  # Test 9: rand for API key
  def generate_api_key
    # VULNERABLE: API key needs crypto random
    key = (0...40).map { rand(16).to_s(16) }.join
    render plain: key
  end

  # Test 10: rand for encryption IV
  def generate_iv
    # VULNERABLE: IV needs crypto random
    iv = (0...16).map { rand(256).chr }.join
    render plain: iv.bytes.map { |b| '%02x' % b }.join
  end

  # Test 11: Random.new instance
  def random_instance
    # VULNERABLE: Random class is not crypto secure
    rng = Random.new
    token = rng.bytes(16).unpack1('H*')
    render plain: token
  end

  # Test 12: Process ID based
  def pid_random
    # VULNERABLE: PID is predictable
    srand(Process.pid)
    render plain: rand.to_s
  end
end

# Note: Secure alternatives in Ruby:
# SecureRandom.hex(16)
# SecureRandom.uuid
# SecureRandom.random_bytes(16)
# SecureRandom.alphanumeric(20)
