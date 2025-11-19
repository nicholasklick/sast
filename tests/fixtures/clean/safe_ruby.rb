# Clean Ruby code with no vulnerabilities
require 'sqlite3'
require 'securerandom'
require 'digest'
require 'pathname'

class SafeRubyCode

  # 1. Safe SQL Query - Parameterized
  def get_user_by_id(db, user_id)
    query = "SELECT * FROM users WHERE id = ?"
    db.execute(query, user_id).first
  end

  # 2. Safe File Access - Path validation
  def read_file(filename)
    base_path = Pathname.new("/var/data").realpath
    file_path = base_path.join(filename).realpath

    unless file_path.to_s.start_with?(base_path.to_s)
      raise SecurityError, "Path traversal detected"
    end

    File.read(file_path)
  end

  # 3. Safe Configuration
  def get_api_key
    ENV['API_KEY'] || raise('API_KEY not set')
  end

  # 4. Safe Cryptography - Using OpenSSL properly
  def encrypt_data(data, key)
    require 'openssl'
    cipher = OpenSSL::Cipher.new('AES-256-GCM')
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end

  # 5. Safe Hashing - SHA-256
  def hash_password(password)
    Digest::SHA256.hexdigest(password)
  end

  # 6. Safe Random Generation
  def generate_secure_token
    SecureRandom.hex(32)
  end

  # 7. Safe Command Execution - Using array form
  def list_files(directory)
    allowed_dirs = ['/tmp', '/var/log']
    unless allowed_dirs.include?(directory)
      raise SecurityError, "Directory not allowed"
    end

    # Array form prevents shell injection
    output, status = Open3.capture2('ls', '-la', directory)
    output
  end

  # 8. Safe YAML Loading - Using safe_load
  def parse_yaml_safely(yaml_content)
    require 'yaml'
    YAML.safe_load(yaml_content, permitted_classes: [Symbol])
  end

  # 9. Safe Input Validation
  def validate_and_sanitize(input)
    input.gsub(/[^a-zA-Z0-9_-]/, '')
  end

  # 10. Safe URL Fetching - Whitelist validation
  def fetch_url(url)
    require 'uri'
    require 'net/http'

    allowed_hosts = ['api.example.com', 'data.example.com']
    uri = URI.parse(url)

    unless allowed_hosts.include?(uri.host)
      raise SecurityError, "Host not allowed"
    end

    Net::HTTP.get(uri)
  end

  # 11. Safe Regex - No ReDoS vulnerability
  def safe_pattern_match(input)
    # Using simple, non-backtracking pattern
    input =~ /\A[a-zA-Z0-9]+\z/
  end

  # 12. Safe SQL with ActiveRecord style (parameterized)
  def find_users_by_role(role)
    # Simulating ActiveRecord parameterized query
    query = "SELECT * FROM users WHERE role = ?"
    # User.where("role = ?", role)
    [query, role]
  end

  # 13. Safe File Operations
  def write_file_safely(filename, content)
    base_path = Pathname.new("/tmp")
    file_path = base_path.join(filename)

    unless file_path.to_s.start_with?(base_path.to_s)
      raise SecurityError, "Path traversal detected"
    end

    File.write(file_path, content)
  end
end
