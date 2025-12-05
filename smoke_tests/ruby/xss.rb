# Cross-Site Scripting (XSS) vulnerabilities in Ruby/Rails
require 'erb'
require 'cgi'

class XssController < ApplicationController
  # Test 1: Direct output without escaping
  def echo
    @message = params[:message]
    # VULNERABLE: Direct output in view without escaping
    # <%= @message %> in ERB would be safe
    # <%== @message %> or raw(@message) is vulnerable
  end

  # Test 2: Using raw helper
  def raw_output
    content = params[:content]
    # VULNERABLE: raw() bypasses escaping
    render html: raw(content)
  end

  # Test 3: html_safe on user input
  def safe_string
    user_input = params[:input]
    # VULNERABLE: Marking user input as safe
    @output = user_input.html_safe
  end

  # Test 4: String interpolation in HTML
  def interpolate
    name = params[:name]
    # VULNERABLE: Direct interpolation
    render html: "<h1>Hello, #{name}</h1>".html_safe
  end

  # Test 5: JavaScript context
  def js_context
    callback = params[:callback]
    # VULNERABLE: User input in JavaScript
    render html: "<script>#{callback}(data);</script>".html_safe
  end

  # Test 6: Haml without escaping
  def haml_output
    @content = params[:content]
    # VULNERABLE: In Haml, != doesn't escape
    # != @content
  end

  # Test 7: ERB with raw output
  def erb_raw
    template = ERB.new("<%= @user_input %>")
    @user_input = params[:input]
    # Actually safe, but if template uses <%== %> it's vulnerable
  end

  # Test 8: link_to with javascript: URL
  def link_output
    url = params[:url]
    # VULNERABLE: javascript: URLs execute code
    @link = link_to("Click here", url)
  end

  # Test 9: content_tag with user content
  def tag_output
    text = params[:text]
    # VULNERABLE: Depending on usage
    render html: content_tag(:div, text.html_safe)
  end

  # Test 10: render inline with user data
  def inline_render
    template = params[:template]
    # VULNERABLE: User controls template
    render inline: template
  end

  # Test 11: JSON response with HTML
  def json_response
    data = params[:data]
    # VULNERABLE: If rendered in browser without Content-Type
    render json: { html: data }
  end
end

# Test 12: Sinatra raw output
require 'sinatra'
get '/echo' do
  # VULNERABLE: Direct output
  params[:message]
end
