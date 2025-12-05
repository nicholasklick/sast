# YAML Deserialization vulnerabilities in Ruby
require 'yaml'
require 'psych'

class YamlController < ApplicationController
  # Test 1: YAML.load with user input
  def parse_yaml
    yaml_content = params[:yaml]
    # VULNERABLE: YAML.load executes arbitrary code
    data = YAML.load(yaml_content)
    render json: data
  end

  # Test 2: YAML.unsafe_load
  def parse_unsafe
    yaml_content = params[:yaml]
    # VULNERABLE: Explicitly unsafe
    data = YAML.unsafe_load(yaml_content)
    render json: data
  end

  # Test 3: Psych.load with permitted_classes
  def parse_psych
    yaml_content = params[:yaml]
    # VULNERABLE: Allowing dangerous classes
    data = Psych.load(yaml_content, permitted_classes: [Symbol, Date, Time, OpenStruct])
    render json: data
  end

  # Test 4: YAML.load_file with user path
  def load_file
    file_path = params[:path]
    # VULNERABLE: Loading YAML from user-controlled path
    data = YAML.load_file(file_path)
    render json: data
  end

  # Test 5: YAML.load_stream
  def load_stream
    yaml_stream = params[:stream]
    # VULNERABLE: YAML.load_stream is also dangerous
    documents = []
    YAML.load_stream(yaml_stream) do |doc|
      documents << doc
    end
    render json: documents
  end

  # Test 6: ERB + YAML
  def load_erb_yaml
    yaml_content = params[:yaml]
    # VULNERABLE: ERB evaluation before YAML parsing
    erb_result = ERB.new(yaml_content).result
    data = YAML.load(erb_result)
    render json: data
  end

  # Test 7: YAML in config
  def update_config
    config_yaml = params[:config]
    # VULNERABLE: Config from user
    config = YAML.load(config_yaml)
    apply_config(config)
    head :ok
  end

  # Test 8: YAML from file upload
  def upload_yaml
    file = params[:file]
    # VULNERABLE: YAML from uploaded file
    data = YAML.load(file.read)
    render json: data
  end

  # Test 9: YAML from database
  def load_from_db
    record = ConfigRecord.find(params[:id])
    # VULNERABLE: If YAML was stored from user input
    config = YAML.load(record.yaml_content)
    render json: config
  end

  # Test 10: Object serialization round-trip
  def serialize_object
    yaml = params[:yaml]
    # VULNERABLE: Deserializing arbitrary objects
    obj = YAML.load(yaml)
    # Object can have malicious initialize or method_missing
    render json: { class: obj.class.name }
  end

  # Test 11: YAML with aliases
  def parse_with_aliases
    yaml_content = params[:yaml]
    # VULNERABLE: Aliases can cause DoS or exploitation
    data = YAML.load(yaml_content, aliases: true)
    render json: data
  end

  private

  def apply_config(config)
    # Apply configuration settings
  end
end

# Dangerous YAML payload example:
# --- !ruby/object:Gem::Installer
# i: x
# --- !ruby/object:Gem::SpecFetcher
# i: y
# --- !ruby/object:Gem::Requirement
# requirements:
#   !ruby/object:Gem::Package::TarReader
#   io: &1 !ruby/object:Net::BufferedIO
#     io: &1 !ruby/object:Gem::Package::TarReader::Entry
#        read: 0
#        header: "abc"
#     debug_output: &1 !ruby/object:Net::WriteAdapter
#        socket: &1 !ruby/object:Gem::RequestSet
#            sets: !ruby/object:Net::WriteAdapter
#                socket: !ruby/module 'Kernel'
#                method_id: :system
#            git_set: id
#        method_id: :resolve
