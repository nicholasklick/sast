# XPath Injection vulnerabilities in Ruby
require 'nokogiri'
require 'rexml/document'

class XpathController < ApplicationController
  # Test 1: Nokogiri XPath with user input
  def search_nokogiri
    username = params[:username]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: User input in XPath
    results = doc.xpath("//user[name='#{username}']")
    render json: results.map(&:to_h)
  end

  # Test 2: Authentication bypass
  def authenticate
    username = params[:username]
    password = params[:password]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: ' or '1'='1 bypasses auth
    xpath = "//user[name='#{username}' and password='#{password}']"
    user = doc.at_xpath(xpath)
    if user
      render json: { authenticated: true }
    else
      render json: { authenticated: false }
    end
  end

  # Test 3: REXML XPath injection
  def search_rexml
    query = params[:query]
    xml = load_users_xml
    doc = REXML::Document.new(xml)
    # VULNERABLE: XPath injection in REXML
    results = REXML::XPath.match(doc, "//item[contains(name, '#{query}')]")
    render json: results.map(&:text)
  end

  # Test 4: Numeric injection
  def get_by_id
    id = params[:id]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: 1 or 1=1 returns all
    result = doc.at_xpath("//user[@id=#{id}]")
    render json: result&.to_h
  end

  # Test 5: OR injection
  def search_by_role
    role = params[:role]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: ' or '1'='1 returns all
    results = doc.xpath("//user[role='#{role}']")
    render json: { count: results.length }
  end

  # Test 6: Function injection
  def search_contains
    pattern = params[:pattern]
    xml = load_items_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: contains() can be manipulated
    results = doc.xpath("//item[contains(description, '#{pattern}')]")
    render json: { count: results.length }
  end

  # Test 7: Axis navigation injection
  def get_parent
    element = params[:element]
    xml = load_data_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: Can navigate to unintended nodes
    results = doc.xpath("//data/#{element}")
    render json: { count: results.length }
  end

  # Test 8: Wildcard injection
  def search_wildcard
    prefix = params[:prefix]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: Wildcard with user input
    results = doc.xpath("//user[starts-with(name, '#{prefix}')]")
    render json: { count: results.length }
  end

  # Test 9: CSS selector injection (Nokogiri)
  def css_search
    selector = params[:selector]
    xml = load_html
    doc = Nokogiri::HTML(xml)
    # VULNERABLE: User controls CSS selector
    results = doc.css(selector)
    render json: { count: results.length }
  end

  # Test 10: Multiple parameters injection
  def advanced_search
    name = params[:name]
    role = params[:role]
    status = params[:status]
    xml = load_users_xml
    doc = Nokogiri::XML(xml)
    # VULNERABLE: Multiple injection points
    xpath = "//user[name='#{name}' and role='#{role}' and status='#{status}']"
    results = doc.xpath(xpath)
    render json: { count: results.length }
  end

  private

  def load_users_xml
    File.read(Rails.root.join('data', 'users.xml'))
  end

  def load_items_xml
    File.read(Rails.root.join('data', 'items.xml'))
  end

  def load_data_xml
    File.read(Rails.root.join('data', 'data.xml'))
  end

  def load_html
    '<html><body><div class="test">content</div></body></html>'
  end
end
