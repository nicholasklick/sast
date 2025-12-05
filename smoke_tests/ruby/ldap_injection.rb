# LDAP Injection vulnerabilities in Ruby
require 'net/ldap'

class LdapController < ApplicationController
  LDAP_HOST = 'ldap.example.com'
  LDAP_BASE = 'dc=example,dc=com'

  # Test 1: Authentication bypass
  def authenticate
    username = params[:username]
    password = params[:password]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: User input in filter
    filter = Net::LDAP::Filter.construct("(&(uid=#{username})(userPassword=#{password}))")

    result = ldap.search(filter: filter)
    if result.any?
      render json: { authenticated: true }
    else
      render json: { authenticated: false }
    end
  end

  # Test 2: User search injection
  def search_user
    query = params[:query]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: Search query from user
    filter = Net::LDAP::Filter.construct("(|(cn=*#{query}*)(mail=*#{query}*))")

    results = ldap.search(filter: filter)
    render json: results.map(&:cn)
  end

  # Test 3: Group membership check
  def check_group
    user = params[:user]
    group = params[:group]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: Both parameters from user
    filter = Net::LDAP::Filter.construct("(&(member=#{user})(cn=#{group}))")

    result = ldap.search(filter: filter)
    render json: { member: result.any? }
  end

  # Test 4: Email lookup
  def find_by_email
    email = params[:email]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: Email from user
    filter = Net::LDAP::Filter.eq('mail', email)

    results = ldap.search(filter: filter)
    render json: results.map { |r| { cn: r.cn, mail: r.mail } }
  end

  # Test 5: Wildcard injection
  def wildcard_search
    prefix = params[:prefix]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: Wildcard with user input
    filter = Net::LDAP::Filter.construct("(cn=#{prefix}*)")

    results = ldap.search(filter: filter)
    render json: results.count
  end

  # Test 6: DN manipulation
  def get_entry
    dn = params[:dn]

    ldap = Net::LDAP.new(host: LDAP_HOST)
    # VULNERABLE: DN from user input
    ldap.search(base: dn, scope: Net::LDAP::SearchScope_BaseObject) do |entry|
      return render json: { cn: entry.cn.first }
    end
    render json: { error: 'Not found' }
  end

  # Test 7: Attribute value injection
  def update_description
    user = params[:user]
    description = params[:description]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    ldap.auth('admin', 'password')

    # VULNERABLE: Description value from user
    dn = "cn=#{user},#{LDAP_BASE}"
    ldap.replace_attribute(dn, :description, description)

    head :ok
  end

  # Test 8: OR clause injection
  def multi_search
    term = params[:term]

    ldap = Net::LDAP.new(host: LDAP_HOST, base: LDAP_BASE)
    # VULNERABLE: Term in OR filter
    filter = Net::LDAP::Filter.construct("(|(cn=#{term})(sn=#{term})(mail=#{term}))")

    results = ldap.search(filter: filter)
    render json: results.count
  end

  # Test 9: Bind with user credentials
  def bind_user
    username = params[:username]
    password = params[:password]

    ldap = Net::LDAP.new(
      host: LDAP_HOST,
      base: LDAP_BASE,
      # VULNERABLE: DN constructed from user input
      auth: { method: :simple, username: "cn=#{username},#{LDAP_BASE}", password: password }
    )

    if ldap.bind
      render json: { success: true }
    else
      render json: { success: false }
    end
  end
end
