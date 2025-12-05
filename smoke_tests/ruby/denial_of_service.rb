# Denial of Service vulnerabilities in Ruby/Rails
require 'json'
require 'nokogiri'
require 'yaml'

class DosController < ApplicationController
  # Test 1: Unbounded array allocation
  def create_array
    size = params[:size].to_i
    # VULNERABLE: User controls array size
    data = Array.new(size)
    render json: { length: data.length }
  end

  # Test 2: Unbounded string multiplication
  def repeat_string
    count = params[:count].to_i
    # VULNERABLE: User controls repetition
    result = 'x' * count
    render plain: result
  end

  # Test 3: ReDoS
  def validate_input
    input = params[:input]
    # VULNERABLE: Catastrophic backtracking
    pattern = /^(a+)+$/
    render json: { match: pattern.match?(input) }
  end

  # Test 4: XML bomb
  def parse_xml
    xml = params[:xml]
    # VULNERABLE: Entity expansion not limited
    doc = Nokogiri::XML(xml) do |config|
      config.noent  # Enables entity substitution
    end
    render plain: doc.to_xml
  end

  # Test 5: YAML deserialization bomb
  def parse_yaml
    yaml = params[:yaml]
    # VULNERABLE: Can contain recursive structures
    data = YAML.unsafe_load(yaml)
    render json: data
  end

  # Test 6: JSON parsing large numbers
  def parse_json
    json = params[:json]
    # VULNERABLE: Large numbers can cause DoS
    data = JSON.parse(json)
    render json: data
  end

  # Test 7: CPU exhaustion
  def compute
    iterations = params[:n].to_i
    # VULNERABLE: User controls computation
    result = 0
    iterations.times { |i| result += Math.sin(i) * Math.cos(i) }
    render json: { result: result }
  end

  # Test 8: File read amplification
  def read_file
    path = params[:path]
    # VULNERABLE: No size limit on file read
    content = File.read(path)
    render plain: content
  end

  # Test 9: Hash collision attack
  def store_data
    # VULNERABLE: Hash collision with crafted keys
    data = {}
    params.each { |k, v| data[k] = v }
    render json: { count: data.size }
  end

  # Test 10: Recursive structure
  def process_nested
    data = params[:data]
    # VULNERABLE: Deep nesting can cause stack overflow
    def deep_process(obj, depth = 0)
      return obj if depth > 1000
      case obj
      when Hash
        obj.transform_values { |v| deep_process(v, depth + 1) }
      when Array
        obj.map { |v| deep_process(v, depth + 1) }
      else
        obj
      end
    end
    result = deep_process(data)
    render json: result
  end

  # Test 11: Synchronous blocking
  def slow_operation
    delay = params[:delay].to_i
    # VULNERABLE: User controls blocking time
    sleep(delay)
    head :ok
  end

  # Test 12: Unbounded loop
  def process_items
    count = params[:count].to_i
    # VULNERABLE: User controls iteration count
    count.times do
      # Do work
      Object.new
    end
    head :ok
  end

  # Test 13: ZIP bomb
  def extract_zip
    file = params[:file]
    temp_path = Rails.root.join('tmp', file.original_filename)
    File.binwrite(temp_path, file.read)
    # VULNERABLE: No decompression ratio limit
    Zip::File.open(temp_path) do |zip_file|
      zip_file.each do |entry|
        entry.extract(Rails.root.join('extracted', entry.name))
      end
    end
    head :ok
  end
end
