# Cross-Site Request Forgery (CSRF) vulnerabilities in Ruby/Rails
class CsrfController < ApplicationController
  # Test 1: Skipping CSRF protection
  skip_before_action :verify_authenticity_token

  def transfer_funds
    amount = params[:amount]
    to_account = params[:to_account]
    # VULNERABLE: No CSRF protection
    current_user.transfer(amount, to_account)
    redirect_to account_path
  end

  # Test 2: State change via GET
  def delete_account
    # VULNERABLE: DELETE via GET request
    User.find(params[:id]).destroy
    redirect_to root_path
  end

  # Test 3: protect_from_forgery except
  protect_from_forgery except: [:change_password]

  def change_password
    # VULNERABLE: Password change without CSRF
    current_user.update(password: params[:new_password])
    redirect_to root_path
  end

  # Test 4: AJAX without CSRF
  protect_from_forgery with: :null_session

  def update_profile
    # VULNERABLE: null_session allows CSRF
    current_user.update(profile_params)
    render json: { success: true }
  end

  # Test 5: API without CSRF
  skip_before_action :verify_authenticity_token, if: :json_request?

  def api_action
    # VULNERABLE: JSON requests without CSRF
    perform_sensitive_action
    render json: { result: 'done' }
  end

  # Test 6: CORS misconfiguration
  def cors_endpoint
    # VULNERABLE: CORS allows any origin with credentials
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    render json: { data: 'sensitive' }
  end

  # Test 7: Cookie without SameSite
  def set_cookie
    # VULNERABLE: No SameSite attribute
    cookies[:auth] = {
      value: 'token',
      httponly: true,
      secure: true
      # SameSite not set
    }
  end

  # Test 8: Admin action without CSRF
  skip_before_action :verify_authenticity_token, only: [:promote_user]

  def promote_user
    # VULNERABLE: Admin action without protection
    User.find(params[:id]).update(role: 'admin')
    redirect_to users_path
  end

  # Test 9: Token in query string
  def process_payment
    token = params[:csrf_token]
    # VULNERABLE: Token in URL can leak via Referer
    if valid_token?(token)
      process_payment_internal
    end
  end

  # Test 10: protect_from_forgery disabled conditionally
  protect_from_forgery unless: -> { request.format.json? }

  def sensitive_json_action
    # VULNERABLE: JSON requests bypass CSRF
    perform_action
    render json: { status: 'ok' }
  end

  private

  def json_request?
    request.format.json?
  end

  def profile_params
    params.require(:profile).permit(:name, :bio)
  end

  def valid_token?(token)
    # Simplified validation
    true
  end

  def perform_sensitive_action; end
  def perform_action; end
  def process_payment_internal; end
end
