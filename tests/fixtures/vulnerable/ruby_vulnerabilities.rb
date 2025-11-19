# Ruby Vulnerability Test Fixtures
require 'sqlite3'
require 'open3'
require 'digest'
require 'openssl'
require 'net/http'

class RubyVulnerabilities

  # 1. SQL Injection - String interpolation
  def sql_injection_interpolation(user_id)
    db = SQLite3::Database.new('test.db')
    query = "SELECT * FROM users WHERE id = '#{user_id}'"
    db.execute(query)
  end

  # 2. SQL Injection - String concatenation
  def sql_injection_concat(username)
    db = SQLite3::Database.new('test.db')
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    db.execute(query)
  end

  # 3. Command Injection - system
  def command_injection_system(filename)
    system("cat #{filename}")
  end

  # 4. Command Injection - backticks
  def command_injection_backticks(user_input)
    `ls #{user_input}`
  end

  # 5. Command Injection - exec
  def command_injection_exec(command)
    exec("sh -c #{command}")
  end

  # 6. Command Injection - Open3
  def command_injection_open3(filename)
    Open3.capture3("cat #{filename}")
  end

  # 7. Path Traversal
  def path_traversal(filename)
    File.read("/var/data/#{filename}")
  end

  # 8. Hardcoded Credentials - API Key
  API_KEY = "sk_live_ruby1234567890abcdef"

  # 9. Hardcoded Credentials - Password
  def connect_to_database
    password = "RubySecret123!"
    "postgresql://admin:#{password}@localhost/db"
  end

  # 10. Weak Cryptography - DES
  def weak_crypto_des(data)
    cipher = OpenSSL::Cipher.new('DES')
    cipher.encrypt
    cipher.key = "12345678"
    cipher.update(data) + cipher.final
  end

  # 11. Weak Cryptography - MD5
  def weak_hash_md5(input)
    Digest::MD5.hexdigest(input)
  end

  # 12. Eval with User Input
  def code_injection(user_code)
    eval(user_code)
  end

  # 13. Unsafe YAML Load
  def unsafe_yaml_load(yaml_content)
    YAML.load(yaml_content)
  end

  # 14. Unsafe Marshal Load
  def unsafe_marshal_load(data)
    Marshal.load(data)
  end

  # 15. SSRF Vulnerability
  def fetch_url(url)
    Net::HTTP.get(URI(url))
  end

  # 16. Open Redirect
  def redirect(url)
    # redirect_to url - vulnerable in Rails
    puts "Redirecting to: #{url}"
  end

  # 17. Mass Assignment (Rails pattern)
  def mass_assignment(params)
    # User.create(params) - vulnerable if params not filtered
    {}
  end

  # 18. Unsafe Regex (ReDoS)
  def unsafe_regex(input)
    # Vulnerable to catastrophic backtracking
    input =~ /(a+)+b/
  end

  # 19. Template Injection (ERB)
  def render_template(user_input)
    require 'erb'
    template = ERB.new("<html><body><h1>Welcome <%= user_input %></h1></body></html>")
    template.result(binding)
  end

  # 20. SQL Injection in ActiveRecord (Rails pattern)
  def sql_injection_activerecord(user_id)
    # User.where("id = #{user_id}") - vulnerable
    "SELECT * FROM users WHERE id = #{user_id}"
  end

  # 21. XSS in Rails View
  def render_html(user_input)
    "<html><body><h1>Welcome #{user_input}</h1></body></html>".html_safe
  end

  # 22. Unsafe File Operations
  def delete_file(filename)
    File.delete("/tmp/#{filename}")
  end

  # 23. Unsafe Random Number Generation
  def generate_token
    rand(1000000).to_s
  end

  # 24. LDAP Injection
  def ldap_injection(username)
    filter = "(uid=#{username})"
    # LDAP query with unvalidated input
    filter
  end

  # 25. NoSQL Injection (MongoDB pattern)
  def mongo_query(user_id)
    { user_id: user_id }  # Vulnerable if user_id contains hash operators
  end
end
