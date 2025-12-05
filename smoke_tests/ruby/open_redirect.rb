# Open Redirect vulnerabilities in Ruby/Rails
class RedirectController < ApplicationController
  # Test 1: Direct redirect from params
  def login_redirect
    return_url = params[:return_url]
    # VULNERABLE: Unvalidated redirect
    redirect_to return_url
  end

  # Test 2: Redirect after authentication
  def after_login
    target = params[:target]
    # VULNERABLE: Can redirect to external site
    redirect_to target and return if target.present?
    redirect_to root_path
  end

  # Test 3: Partial validation bypass
  def safe_redirect
    url = params[:url]
    # VULNERABLE: Can be bypassed with //evil.com
    if url.start_with?('/')
      redirect_to url
    else
      redirect_to root_path
    end
  end

  # Test 4: Session-based redirect
  def restore_location
    return_url = session[:return_url]
    # VULNERABLE: Session value can be manipulated
    redirect_to return_url if return_url
  end

  # Test 5: Cookie-based redirect
  def cookie_redirect
    target = cookies[:redirect_target]
    # VULNERABLE: Cookie can be manipulated
    redirect_to target if target.present?
  end

  # Test 6: Header-based redirect
  def referer_redirect
    referer = request.headers['X-Return-Url']
    # VULNERABLE: Header from client
    redirect_to referer if referer
  end

  # Test 7: Domain validation bypass
  def domain_check
    url = params[:url]
    # VULNERABLE: evil.example.com contains example.com
    if url.include?('example.com')
      redirect_to url
    else
      redirect_to root_path
    end
  end

  # Test 8: JavaScript redirect
  def js_redirect
    url = params[:url]
    # VULNERABLE: JavaScript redirect
    render html: "<script>window.location='#{url}';</script>".html_safe
  end

  # Test 9: Meta refresh redirect
  def meta_redirect
    target = params[:target]
    # VULNERABLE: Meta refresh with user URL
    render html: "<meta http-equiv='refresh' content='0;url=#{target}'>".html_safe
  end

  # Test 10: URL from database
  def dynamic_redirect
    redirect_config = RedirectConfig.find_by(name: params[:name])
    # VULNERABLE: If database value came from user input
    redirect_to redirect_config.url
  end

  # Test 11: Redirect with path traversal
  def path_redirect
    path = params[:path]
    # VULNERABLE: Can add protocol with //
    redirect_to "/app/#{path}"
  end
end

# Sinatra example
require 'sinatra'
get '/redirect' do
  # VULNERABLE: Direct redirect
  redirect params[:url]
end
