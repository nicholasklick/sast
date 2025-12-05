# Sensitive Data Exposure vulnerabilities in Ruby/Rails
class SensitiveDataController < ApplicationController
  # Test 1: Exception details exposed
  def show_error
    begin
      raise_error
    rescue => e
      # VULNERABLE: Stack trace exposed
      render plain: "Error: #{e.message}\n#{e.backtrace.join("\n")}"
    end
  end

  # Test 2: Debug info in response
  def get_data
    data = load_data
    # VULNERABLE: Debug information exposed
    render json: {
      data: data,
      debug: {
        server: Socket.gethostname,
        user: ENV['USER'],
        rails_env: Rails.env
      }
    }
  end

  # Test 3: Logging sensitive data
  def process_payment
    card_number = params[:card_number]
    cvv = params[:cvv]
    # VULNERABLE: Credit card data logged
    Rails.logger.info "Processing card: #{card_number}, CVV: #{cvv}"
    process_card(card_number, cvv)
    head :ok
  end

  # Test 4: Sensitive data in URL
  def show_account
    ssn = params[:ssn]
    account = params[:account_number]
    # VULNERABLE: SSN and account in URL (logged, cached)
    @user = User.find_by(ssn: ssn)
    render :show
  end

  # Test 5: Caching sensitive responses
  def get_user_details
    # VULNERABLE: Sensitive data being cached
    expires_in 1.hour
    render json: {
      user_id: current_user.id,
      email: current_user.email,
      ssn: current_user.ssn
    }
  end

  # Test 6: Unencrypted sensitive storage
  def store_ssn
    ssn = params[:ssn]
    # VULNERABLE: SSN stored unencrypted
    File.write('/data/user.txt', ssn)
    head :ok
  end

  # Test 7: API key in response
  def get_config
    # VULNERABLE: API keys exposed
    render json: {
      api_endpoint: 'https://api.example.com',
      api_key: 'sk-12345-secret-key',
      db_password: 'secret123'
    }
  end

  # Test 8: Missing security headers
  def secure_page
    # VULNERABLE: No security headers set
    # Missing: X-Content-Type-Options, X-Frame-Options, CSP
    render :secure
  end

  # Test 9: HTTP for sensitive data
  def redirect_to_payment
    # VULNERABLE: HTTP for payment page
    redirect_to 'http://payment.example.com/checkout'
  end

  # Test 10: Instance variables with PII
  def profile
    @ssn = current_user.ssn
    @credit_card = current_user.credit_card
    # VULNERABLE: PII in instance variables exposed to view
    render :profile
  end

  # Test 11: Verbose errors in JSON API
  def api_error
    begin
      process_api_request
    rescue => e
      # VULNERABLE: Full error details in API response
      render json: {
        error: e.message,
        backtrace: e.backtrace,
        class: e.class.name
      }, status: 500
    end
  end

  # Test 12: Secrets in view
  def admin_panel
    @database_url = ENV['DATABASE_URL']
    @secret_key = Rails.application.secrets.secret_key_base
    # VULNERABLE: Secrets passed to view
    render :admin_panel
  end

  private

  def raise_error
    raise StandardError, 'Something went wrong'
  end

  def load_data
    {}
  end

  def process_card(number, cvv); end
  def process_api_request; end
end
