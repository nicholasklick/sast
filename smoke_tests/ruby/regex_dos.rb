# Regular Expression DoS (ReDoS) vulnerabilities in Ruby
class RegexController < ApplicationController
  # Test 1: Nested quantifiers
  def validate_nested
    input = params[:input]
    # VULNERABLE: (a+)+ causes exponential backtracking
    pattern = /(a+)+b/
    render json: { match: pattern.match?(input) }
  end

  # Test 2: Overlapping alternation
  def check_overlap
    input = params[:input]
    # VULNERABLE: Overlapping alternatives
    pattern = /(a|a)+b/
    render json: { match: pattern.match?(input) }
  end

  # Test 3: Email validation ReDoS
  def validate_email
    email = params[:email]
    # VULNERABLE: Classic email ReDoS pattern
    pattern = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]+)+$/
    render json: { valid: pattern.match?(email) }
  end

  # Test 4: URL validation ReDoS
  def validate_url
    url = params[:url]
    # VULNERABLE: Nested groups in URL pattern
    pattern = /^(https?:\/\/)?([a-zA-Z0-9.-]+)+(\/.*)*$/
    render json: { valid: pattern.match?(url) }
  end

  # Test 5: User-supplied regex
  def custom_match
    input = params[:input]
    pattern_str = params[:pattern]
    # VULNERABLE: User supplies regex pattern
    pattern = Regexp.new(pattern_str)
    render json: { match: pattern.match?(input) }
  end

  # Test 6: gsub with vulnerable pattern
  def replace_pattern
    input = params[:input]
    # VULNERABLE: Vulnerable pattern in gsub
    result = input.gsub(/(a+)+/, 'X')
    render plain: result
  end

  # Test 7: scan with backtracking
  def scan_input
    input = params[:input]
    # VULNERABLE: Scan with exponential pattern
    matches = input.scan(/(.+)+x/)
    render json: { count: matches.length }
  end

  # Test 8: split with ReDoS
  def split_input
    input = params[:input]
    # VULNERABLE: Split can trigger ReDoS
    parts = input.split(/(\s+)+/)
    render json: { parts: parts }
  end

  # Test 9: HTML tag matching ReDoS
  def match_html
    html = params[:html]
    # VULNERABLE: Complex HTML pattern
    pattern = /<([a-z]+)([^>]*)*>/
    matches = html.scan(pattern)
    render json: { count: matches.length }
  end

  # Test 10: Multiline ReDoS
  def multiline_match
    content = params[:content]
    # VULNERABLE: Multiline with backtracking
    pattern = /^(.+)+$/m
    render json: { match: pattern.match?(content) }
  end

  # Test 11: Regex from database
  def dynamic_regex
    config = PatternConfig.find(params[:id])
    input = params[:input]
    # VULNERABLE: Pattern from database (could be user-supplied)
    pattern = Regexp.new(config.pattern)
    render json: { match: pattern.match?(input) }
  end

  # Test 12: Case insensitive ReDoS
  def case_insensitive
    input = params[:input]
    # VULNERABLE: Case insensitive can make it worse
    pattern = /([a-z]+)+$/i
    render json: { match: pattern.match?(input) }
  end
end
