# Unsafe Reflection vulnerabilities in Ruby
class ReflectionController < ApplicationController
  # Test 1: constantize with user input
  def load_class
    class_name = params[:class]
    # VULNERABLE: User controls class instantiation
    klass = class_name.constantize
    render json: { class: klass.name }
  end

  # Test 2: Object.const_get with user input
  def get_constant
    const_name = params[:const]
    # VULNERABLE: User controls constant access
    value = Object.const_get(const_name)
    render json: { value: value.to_s }
  end

  # Test 3: send with user method name
  def invoke_method
    method_name = params[:method]
    obj = SomeService.new
    # VULNERABLE: User controls method invocation
    result = obj.send(method_name)
    render json: { result: result }
  end

  # Test 4: public_send with user method
  def public_invoke
    method_name = params[:method]
    args = params[:args]
    obj = SomeService.new
    # VULNERABLE: User controls method and args
    result = obj.public_send(method_name, *args)
    render json: { result: result }
  end

  # Test 5: __send__ with user method
  def direct_send
    method_name = params[:method]
    obj = SomeService.new
    # VULNERABLE: Direct send with user input
    result = obj.__send__(method_name)
    render json: { result: result }
  end

  # Test 6: instance_variable_get
  def get_ivar
    var_name = params[:var]
    obj = SomeService.new
    # VULNERABLE: User controls instance variable access
    value = obj.instance_variable_get("@#{var_name}")
    render json: { value: value }
  end

  # Test 7: instance_variable_set
  def set_ivar
    var_name = params[:var]
    value = params[:value]
    obj = SomeService.new
    # VULNERABLE: User controls instance variable modification
    obj.instance_variable_set("@#{var_name}", value)
    head :ok
  end

  # Test 8: eval with user input
  def evaluate
    code = params[:code]
    # VULNERABLE: Code execution
    result = eval(code)
    render json: { result: result }
  end

  # Test 9: class_eval with user input
  def class_modify
    code = params[:code]
    # VULNERABLE: Class modification
    SomeService.class_eval(code)
    head :ok
  end

  # Test 10: instance_eval with user input
  def instance_modify
    code = params[:code]
    obj = SomeService.new
    # VULNERABLE: Instance-level code execution
    result = obj.instance_eval(code)
    render json: { result: result }
  end

  # Test 11: define_method with user name
  def create_method
    method_name = params[:method_name]
    body = params[:body]
    # VULNERABLE: Dynamic method creation
    SomeService.define_method(method_name) do
      eval(body)
    end
    head :ok
  end

  # Test 12: method with user name
  def get_method
    method_name = params[:method]
    obj = SomeService.new
    # VULNERABLE: Accessing method by name
    m = obj.method(method_name)
    result = m.call
    render json: { result: result }
  end
end

class SomeService
  def initialize
    @secret = 'sensitive_data'
  end

  def public_action
    'public result'
  end

  private

  def private_action
    'private result'
  end
end
