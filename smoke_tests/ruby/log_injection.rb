# Log Injection vulnerabilities in Ruby
require 'logger'

class LogInjectionController < ApplicationController
  # Test 1: Rails logger with user input
  def log_action
    username = params[:username]
    # VULNERABLE: Username can contain newlines
    Rails.logger.info "User #{username} logged in"
  end

  # Test 2: Standard Logger
  def log_message
    message = params[:message]
    logger = Logger.new('/var/log/app.log')
    # VULNERABLE: Message not sanitized
    logger.info message
  end

  # Test 3: puts to log
  def debug_log
    data = params[:data]
    # VULNERABLE: Direct output to STDOUT
    puts "Processing: #{data}"
    head :ok
  end

  # Test 4: File.write logging
  def file_log
    event = params[:event]
    # VULNERABLE: Event can contain CRLF
    File.open('/var/log/events.log', 'a') do |f|
      f.puts "[#{Time.now}] #{event}"
    end
    head :ok
  end

  # Test 5: JSON log format breaking
  def json_log
    message = params[:message]
    # VULNERABLE: Can break JSON structure
    log_entry = { timestamp: Time.now, message: message }.to_json
    File.open('/var/log/json.log', 'a') { |f| f.puts log_entry }
    head :ok
  end

  # Test 6: Syslog injection
  def syslog_message
    user_input = params[:input]
    # VULNERABLE: User input in syslog
    Syslog.open('myapp') do |s|
      s.info user_input
    end
    head :ok
  end

  # Test 7: Exception message logging
  def log_exception
    begin
      raise params[:error]
    rescue => e
      # VULNERABLE: Exception message from user
      Rails.logger.error "Exception: #{e.message}"
    end
    head :ok
  end

  # Test 8: Audit log manipulation
  def audit_log
    user = params[:user]
    action = params[:action]
    result = params[:result]
    # VULNERABLE: Multiple fields can contain newlines
    audit = "User: #{user}\nAction: #{action}\nResult: #{result}"
    File.open('/var/log/audit.log', 'a') { |f| f.puts audit }
    head :ok
  end

  # Test 9: WARN level logging
  def warn_log
    warning = params[:warning]
    # VULNERABLE: Warning from user input
    Rails.logger.warn "Warning: #{warning}"
    head :ok
  end

  # Test 10: Debug logging in production
  def debug_info
    debug_data = params[:debug]
    # VULNERABLE: Debug info in production
    Rails.logger.debug "Debug: #{debug_data}"
    head :ok
  end

  # Test 11: Tagged logging
  def tagged_log
    tag = params[:tag]
    message = params[:message]
    # VULNERABLE: Both tag and message from user
    Rails.logger.tagged(tag) do
      Rails.logger.info message
    end
    head :ok
  end
end
