# Server-Side Request Forgery (SSRF) vulnerabilities in Ruby
require 'net/http'
require 'open-uri'
require 'faraday'
require 'httparty'
require 'rest-client'

class SsrfController < ApplicationController
  # Test 1: Net::HTTP with user URL
  def fetch_url
    url = params[:url]
    uri = URI.parse(url)
    # VULNERABLE: User-controlled URL
    response = Net::HTTP.get(uri)
    render plain: response
  end

  # Test 2: open-uri with user URL
  def open_url
    url = params[:url]
    # VULNERABLE: open-uri follows redirects
    content = URI.open(url).read
    render plain: content
  end

  # Test 3: Faraday with user URL
  def faraday_fetch
    url = params[:url]
    # VULNERABLE: User-controlled URL
    response = Faraday.get(url)
    render plain: response.body
  end

  # Test 4: HTTParty with user URL
  def httparty_fetch
    url = params[:url]
    # VULNERABLE: User-controlled URL
    response = HTTParty.get(url)
    render plain: response.body
  end

  # Test 5: RestClient with user URL
  def rest_fetch
    url = params[:url]
    # VULNERABLE: User-controlled URL
    response = RestClient.get(url)
    render plain: response.body
  end

  # Test 6: Partial URL construction
  def fetch_from_host
    host = params[:host]
    # VULNERABLE: User controls hostname
    url = "http://#{host}/api/data"
    response = Net::HTTP.get(URI.parse(url))
    render plain: response
  end

  # Test 7: Port scanning via SSRF
  def check_port
    port = params[:port]
    # VULNERABLE: User controls port
    uri = URI.parse("http://internal-server:#{port}/")
    begin
      Net::HTTP.get(uri)
      render json: { status: 'open' }
    rescue
      render json: { status: 'closed' }
    end
  end

  # Test 8: Image proxy
  def image_proxy
    image_url = params[:src]
    # VULNERABLE: Can fetch internal resources
    uri = URI.parse(image_url)
    response = Net::HTTP.get_response(uri)
    send_data response.body, type: 'image/png'
  end

  # Test 9: Webhook URL
  def send_webhook
    webhook_url = params[:webhook]
    data = params[:data]
    # VULNERABLE: User-controlled webhook
    uri = URI.parse(webhook_url)
    Net::HTTP.post(uri, data.to_json)
    head :ok
  end

  # Test 10: File protocol SSRF
  def read_resource
    uri = params[:uri]
    # VULNERABLE: Could be file:///etc/passwd with open-uri
    content = URI.open(uri).read
    render plain: content
  end

  # Test 11: DNS rebinding
  def fetch_external
    domain = params[:domain]
    # VULNERABLE: DNS can resolve to internal IP
    url = "http://#{domain}/data"
    response = Net::HTTP.get(URI.parse(url))
    render plain: response
  end
end
