# HTTP Header Injection vulnerabilities in Ruby/Rails
class HeaderInjectionController < ApplicationController
  # Test 1: Response splitting via Location header
  def redirect_header
    target = params[:target]
    # VULNERABLE: CRLF can inject headers
    response.headers['Location'] = target
    head :found
  end

  # Test 2: Cookie value injection
  def set_cookie_header
    value = params[:value]
    # VULNERABLE: Value can contain CRLF
    cookies[:session] = value
    head :ok
  end

  # Test 3: Content-Disposition header
  def download_file
    filename = params[:filename]
    # VULNERABLE: Filename can contain CRLF
    response.headers['Content-Disposition'] = "attachment; filename=\"#{filename}\""
    send_data 'content', type: 'application/octet-stream'
  end

  # Test 4: Custom header with user input
  def custom_header
    header_value = params[:header]
    # VULNERABLE: User controls header value
    response.headers['X-Custom-Header'] = header_value
    head :ok
  end

  # Test 5: Cache-Control injection
  def set_cache
    directive = params[:cache]
    # VULNERABLE: User controls caching
    response.headers['Cache-Control'] = directive
    head :ok
  end

  # Test 6: CORS header injection
  def cors_response
    origin = request.headers['Origin']
    # VULNERABLE: Reflecting origin without validation
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    render json: { data: 'sensitive' }
  end

  # Test 7: WWW-Authenticate header
  def require_auth
    realm = params[:realm]
    # VULNERABLE: Realm from user input
    response.headers['WWW-Authenticate'] = "Basic realm=\"#{realm}\""
    head :unauthorized
  end

  # Test 8: Link header injection
  def add_link_header
    url = params[:preload]
    # VULNERABLE: URL in Link header
    response.headers['Link'] = "<#{url}>; rel=preload"
    head :ok
  end

  # Test 9: Content-Type header
  def set_content_type
    content_type = params[:type]
    # VULNERABLE: User controls content type
    response.content_type = content_type
    render plain: 'data'
  end

  # Test 10: X-Forwarded-For reflection
  def log_ip
    ip = request.headers['X-Forwarded-For']
    # VULNERABLE: Header reflected back
    response.headers['X-Client-IP'] = ip
    head :ok
  end

  # Test 11: Rack response headers
  def rack_headers
    header_name = params[:name]
    header_value = params[:value]
    # VULNERABLE: User controls header name and value
    response.headers[header_name] = header_value
    head :ok
  end

  # Test 12: Set-Cookie via header
  def raw_cookie
    name = params[:name]
    value = params[:value]
    # VULNERABLE: Can inject additional cookies
    response.headers['Set-Cookie'] = "#{name}=#{value}"
    head :ok
  end
end
