# Authentication vulnerabilities in Ruby/Rails
require 'bcrypt'
require 'digest'

class AuthController < ApplicationController
  # Test 1: Plaintext password storage
  def register_plaintext
    user = User.new
    user.username = params[:username]
    # VULNERABLE: Storing plaintext password
    user.password = params[:password]
    user.save
    redirect_to root_path
  end

  # Test 2: MD5 password hashing
  def register_md5
    user = User.new
    user.username = params[:username]
    # VULNERABLE: MD5 is too weak
    user.password_hash = Digest::MD5.hexdigest(params[:password])
    user.save
    redirect_to root_path
  end

  # Test 3: SHA1 without salt
  def register_sha1
    user = User.new
    # VULNERABLE: Unsalted SHA1
    user.password_hash = Digest::SHA1.hexdigest(params[:password])
    user.save
    redirect_to root_path
  end

  # Test 4: Hardcoded credentials
  def admin_login
    username = params[:username]
    password = params[:password]
    # VULNERABLE: Hardcoded credentials
    if username == 'admin' && password == 'admin123'
      session[:admin] = true
      redirect_to admin_path
    else
      render :login
    end
  end

  # Test 5: Timing attack in comparison
  def login_timing
    user = User.find_by(username: params[:username])
    # VULNERABLE: String comparison leaks timing
    if user && user.password_hash == hash_password(params[:password])
      session[:user_id] = user.id
      redirect_to root_path
    else
      render :login
    end
  end

  # Test 6: No account lockout
  def login_no_lockout
    user = User.find_by(username: params[:username])
    # VULNERABLE: No failed attempt tracking
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
      redirect_to root_path
    else
      flash[:error] = 'Invalid credentials'
      render :login
    end
  end

  # Test 7: Password in URL (GET request)
  def login_get
    username = params[:username]
    password = params[:password]
    # VULNERABLE: GET request with credentials
    authenticate_user(username, password)
  end

  # Test 8: Password logged
  def login_with_logging
    Rails.logger.info "Login attempt: #{params[:username]}/#{params[:password]}"
    # VULNERABLE: Password in logs
    authenticate_user(params[:username], params[:password])
  end

  # Test 9: Weak session configuration
  def create_session
    # VULNERABLE: Insecure cookie settings
    cookies[:session_id] = {
      value: SecureRandom.hex,
      httponly: false,  # XSS vulnerable
      secure: false     # Sent over HTTP
    }
  end

  # Test 10: Insufficient password requirements
  def set_password
    password = params[:password]
    # VULNERABLE: No complexity check
    if password.length >= 4  # Too short
      current_user.update(password: password)
      redirect_to root_path
    else
      flash[:error] = 'Password too short'
      render :password
    end
  end

  # Test 11: Remember me with predictable token
  def remember_me
    # VULNERABLE: Predictable remember token
    token = user.id.to_s + Time.now.to_i.to_s
    cookies.permanent[:remember_token] = token
  end

  # Test 12: Session fixation
  def login_no_regenerate
    if authenticate_user(params[:username], params[:password])
      # VULNERABLE: Session not regenerated after login
      session[:user_id] = @user.id
      redirect_to root_path
    end
  end

  private

  def hash_password(password)
    Digest::SHA256.hexdigest(password)
  end

  def authenticate_user(username, password)
    @user = User.find_by(username: username)
    @user&.authenticate(password)
  end
end
