# Session Management vulnerabilities in Ruby/Rails
class SessionController < ApplicationController
  # Test 1: Session fixation - no regeneration after login
  def login
    user = User.find_by(username: params[:username])
    if user&.authenticate(params[:password])
      # VULNERABLE: Session not regenerated
      session[:user_id] = user.id
      redirect_to root_path
    else
      render :login
    end
  end

  # Test 2: Session ID in URL
  def show_with_session
    # VULNERABLE: Session ID in URL (logged, shared)
    redirect_to root_path(session_id: session.id)
  end

  # Test 3: Long session expiration
  def remember_me
    session[:user_id] = current_user.id
    # VULNERABLE: Very long session lifetime
    session[:expires_at] = 10.years.from_now
  end

  # Test 4: No session timeout
  def active_session
    # VULNERABLE: No idle timeout check
    if session[:user_id]
      @user = User.find(session[:user_id])
    end
  end

  # Test 5: Predictable session token
  def create_session_token
    # VULNERABLE: Predictable session identifier
    token = "session_#{current_user.id}_#{Time.now.to_i}"
    session[:token] = token
  end

  # Test 6: Session data in cookie without encryption
  def store_sensitive
    # VULNERABLE: If cookie store without encryption
    session[:credit_card] = params[:card_number]
    session[:ssn] = params[:ssn]
  end

  # Test 7: No HttpOnly flag
  def set_session_cookie
    # VULNERABLE: No HttpOnly
    cookies[:session] = {
      value: SecureRandom.hex,
      httponly: false
    }
  end

  # Test 8: No Secure flag
  def set_insecure_cookie
    # VULNERABLE: Cookie sent over HTTP
    cookies[:auth] = {
      value: SecureRandom.hex,
      secure: false
    }
  end

  # Test 9: Insufficient session entropy
  def generate_session
    # VULNERABLE: Low entropy session ID
    session_id = rand(1_000_000).to_s
    cookies[:session_id] = session_id
  end

  # Test 10: Session not invalidated on logout
  def logout
    # VULNERABLE: Session not properly destroyed
    session[:user_id] = nil
    # session.destroy or reset_session not called
    redirect_to root_path
  end

  # Test 11: Concurrent session not controlled
  def login_concurrent
    user = authenticate_user
    # VULNERABLE: No concurrent session limit
    session[:user_id] = user.id
    # Previous sessions not invalidated
  end

  # Test 12: Session stored sensitive data
  def store_token
    # VULNERABLE: Sensitive data in session
    session[:api_token] = params[:token]
    session[:password] = params[:password]
  end

  private

  def authenticate_user
    User.find_by(username: params[:username])
  end
end

# Additional vulnerable configuration examples:
# config/initializers/session_store.rb
# Rails.application.config.session_store :cookie_store,
#   key: '_myapp_session',
#   expire_after: nil,  # VULNERABLE: No expiration
#   httponly: false,    # VULNERABLE: XSS can steal session
#   secure: false       # VULNERABLE: Sent over HTTP
