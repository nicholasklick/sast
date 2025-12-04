# Insecure Deserialization vulnerabilities in Ruby
require 'yaml'
require 'json'
require 'marshal'

class DeserializationVulnerabilities
  def unsafe_yaml_load(user_input)
    # VULNERABLE: YAML.load can execute arbitrary code
    YAML.load(user_input)
  end

  def unsafe_marshal_load(data)
    # VULNERABLE: Marshal.load is dangerous with untrusted data
    Marshal.load(data)
  end

  def unsafe_eval(code)
    # VULNERABLE: eval with user input
    eval(code)
  end

  def unsafe_instance_eval(user_code)
    # VULNERABLE: instance_eval with user input
    instance_eval(user_code)
  end

  def unsafe_send(method_name, *args)
    # VULNERABLE: Dynamic method invocation
    send(method_name, *args)
  end

  def unsafe_constantize(class_name)
    # VULNERABLE: Arbitrary class instantiation
    class_name.constantize.new
  end

  def erb_injection(template)
    # VULNERABLE: ERB template injection
    ERB.new(template).result
  end
end
