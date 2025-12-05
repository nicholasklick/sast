# Mass Assignment vulnerabilities in Ruby/Rails
class User < ApplicationRecord
  # Test 1: No attribute protection (older Rails)
  # VULNERABLE: All attributes assignable
  # attr_accessible should whitelist
end

class UsersController < ApplicationController
  # Test 2: permit without filtering sensitive fields
  def create
    # VULNERABLE: is_admin should not be permitted
    @user = User.new(user_params)
    @user.save
    redirect_to @user
  end

  # Test 3: Permit all attributes
  def update
    @user = User.find(params[:id])
    # VULNERABLE: Permitting all attributes
    @user.update(params.require(:user).permit!)
    redirect_to @user
  end

  # Test 4: Using params directly
  def create_unsafe
    # VULNERABLE: Using params hash directly
    @user = User.new(params[:user])
    @user.save
    redirect_to @user
  end

  # Test 5: Permit includes sensitive field
  def register
    @user = User.new(registration_params)
    @user.save
    redirect_to root_path
  end

  # Test 6: attributes= with hash
  def bulk_update
    @user = User.find(params[:id])
    # VULNERABLE: Direct attribute assignment
    @user.attributes = params[:user]
    @user.save
    redirect_to @user
  end

  # Test 7: update_attributes with unpermitted
  def modify
    @user = User.find(params[:id])
    # VULNERABLE: Legacy method with hash
    @user.update_attributes(params[:user].to_unsafe_h)
    redirect_to @user
  end

  # Test 8: assign_attributes
  def partial_update
    @user = User.find(params[:id])
    # VULNERABLE: Assigning all params
    @user.assign_attributes(params[:user].to_unsafe_h)
    @user.save
    redirect_to @user
  end

  # Test 9: Nested attributes without filtering
  def create_with_profile
    # VULNERABLE: Nested profile might have sensitive fields
    @user = User.new(params.require(:user).permit(:name, :email,
                     profile_attributes: [:id, :bio, :is_verified]))
    @user.save
    redirect_to @user
  end

  # Test 10: to_unsafe_h usage
  def unsafe_hash
    @user = User.find(params[:id])
    # VULNERABLE: Converting to unsafe hash
    @user.update(params[:user].to_unsafe_h)
    redirect_to @user
  end

  private

  # Test 11: Permit includes admin flag
  def user_params
    # VULNERABLE: is_admin, balance, role should not be permitted
    params.require(:user).permit(:username, :email, :password, :is_admin, :balance, :role)
  end

  def registration_params
    # VULNERABLE: role should not be permitted during registration
    params.require(:user).permit(:username, :email, :password, :role)
  end
end

# Test 12: ActiveModel without strong params
class Account
  include ActiveModel::Model

  attr_accessor :name, :email, :balance, :is_admin

  def initialize(attributes = {})
    # VULNERABLE: No filtering of attributes
    attributes.each do |key, value|
      send("#{key}=", value)
    end
  end
end
