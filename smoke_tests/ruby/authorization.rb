# Authorization vulnerabilities in Ruby/Rails
class AuthorizationController < ApplicationController
  # Test 1: Missing authorization check
  def admin_dashboard
    # VULNERABLE: No authorization check
    @users = User.all
    render :admin_dashboard
  end

  # Test 2: IDOR - Insecure Direct Object Reference
  def view_document
    document_id = params[:id]
    # VULNERABLE: No ownership check
    @document = Document.find(document_id)
    render :show
  end

  # Test 3: Horizontal privilege escalation
  def view_profile
    user_id = params[:user_id]
    # VULNERABLE: Can view any user's profile
    @profile = UserProfile.find_by(user_id: user_id)
    render :profile
  end

  # Test 4: Vertical privilege escalation
  def delete_user
    # VULNERABLE: No admin check
    User.find(params[:id]).destroy
    redirect_to users_path
  end

  # Test 5: Client-side authorization
  def get_secret_data
    # VULNERABLE: Relying on JavaScript for authorization
    render json: { secret: 'sensitive data' }
  end

  # Test 6: Predictable resource IDs
  def get_order
    order_id = params[:id]
    # VULNERABLE: Sequential IDs allow enumeration
    @order = Order.find(order_id)
    render json: @order
  end

  # Test 7: Missing function level access control
  def execute_function
    function = params[:function]
    # VULNERABLE: No permission check
    send(function)
  end

  # Test 8: Path-based authorization bypass
  def admin_api
    path = request.path
    # VULNERABLE: Can bypass with case or encoding
    if path.downcase.start_with?('/admin')
      render json: { data: 'admin data' }
    else
      head :unauthorized
    end
  end

  # Test 9: Check after action
  def update_settings
    # VULNERABLE: Action happens before authorization
    SystemSettings.update(params[:settings])
    unless current_user.admin?
      head :unauthorized
      return
    end
    redirect_to settings_path
  end

  # Test 10: Trusting user-provided role
  def action_with_role
    role = request.headers['X-User-Role']
    # VULNERABLE: Trusting client header
    if role == 'admin'
      render json: { admin_data: true }
    else
      head :forbidden
    end
  end

  # Test 11: Cached authorization
  def cached_admin_page
    # VULNERABLE: Cached page served to non-admins
    expires_in 1.hour, public: true
    render :admin_page
  end

  # Test 12: before_action bypass
  skip_before_action :require_admin, only: [:sensitive_action]

  def sensitive_action
    # VULNERABLE: Skipped authorization
    @secrets = Secret.all
    render json: @secrets
  end
end
