# SQL Injection vulnerabilities in Ruby
require 'sqlite3'
require 'active_record'

class SqlInjectionVulnerabilities
  def get_user_unsafe(user_id)
    # VULNERABLE: String interpolation in SQL
    db = SQLite3::Database.new('app.db')
    db.execute("SELECT * FROM users WHERE id = '#{user_id}'")
  end

  def login_unsafe(username, password)
    # VULNERABLE: SQL injection in login
    User.where("username = '#{username}' AND password = '#{password}'").first
  end

  def search_unsafe(term)
    # VULNERABLE: SQL injection in search
    ActiveRecord::Base.connection.execute(
      "SELECT * FROM products WHERE name LIKE '%#{term}%'"
    )
  end

  def find_by_name(name)
    # VULNERABLE: find_by_sql with interpolation
    User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
  end

  def delete_record(table, id)
    # VULNERABLE: Table name injection
    ActiveRecord::Base.connection.execute("DELETE FROM #{table} WHERE id = #{id}")
  end
end
