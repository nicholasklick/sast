# ERB/Template Injection vulnerabilities in Ruby
require 'erb'
require 'erubis'

class TemplateInjectionController < ApplicationController
  # Test 1: ERB with user input as template
  def render_template
    template = params[:template]
    # VULNERABLE: User controls ERB template
    erb = ERB.new(template)
    result = erb.result(binding)
    render plain: result
  end

  # Test 2: ERB.new with binding
  def custom_template
    content = params[:content]
    @user_data = params[:data]
    # VULNERABLE: User content as template
    erb = ERB.new(content)
    output = erb.result(binding)
    render html: output.html_safe
  end

  # Test 3: render inline with user template
  def inline_template
    template = params[:template]
    # VULNERABLE: render inline with user input
    render inline: template
  end

  # Test 4: render with type and user template
  def typed_template
    template = params[:template]
    # VULNERABLE: ERB template from user
    render inline: template, type: :erb
  end

  # Test 5: Erubis with user template
  def erubis_template
    template = params[:template]
    # VULNERABLE: Erubis template injection
    eruby = Erubis::Eruby.new(template)
    result = eruby.result(binding)
    render plain: result
  end

  # Test 6: HAML template injection
  def haml_template
    template = params[:template]
    # VULNERABLE: HAML from user
    engine = Haml::Engine.new(template)
    output = engine.render
    render html: output.html_safe
  end

  # Test 7: Slim template injection
  def slim_template
    template = params[:template]
    # VULNERABLE: Slim from user
    output = Slim::Template.new { template }.render
    render html: output.html_safe
  end

  # Test 8: Liquid template with user template
  def liquid_template
    template = params[:template]
    data = params[:data]
    # VULNERABLE if Liquid not properly sandboxed
    liquid = Liquid::Template.parse(template)
    output = liquid.render(data)
    render plain: output
  end

  # Test 9: Mustache template injection
  def mustache_template
    template = params[:template]
    data = params[:data]
    # VULNERABLE: Template from user
    output = Mustache.render(template, data)
    render plain: output
  end

  # Test 10: Template file path from user
  def file_template
    template_name = params[:template]
    # VULNERABLE: Path traversal in template name
    render template: "templates/#{template_name}"
  end

  # Test 11: Partial with user name
  def partial_injection
    partial_name = params[:partial]
    # VULNERABLE: Partial name from user
    render partial: partial_name
  end

  # Test 12: Layout from user input
  def custom_layout
    layout_name = params[:layout]
    # VULNERABLE: Layout from user
    render :show, layout: layout_name
  end
end
