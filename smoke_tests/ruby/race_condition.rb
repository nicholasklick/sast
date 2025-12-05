# Race Condition vulnerabilities in Ruby/Rails
class RaceConditionController < ApplicationController
  @@balance = 1000
  @@counter = 0

  # Test 1: Check-then-act on balance
  def withdraw
    amount = params[:amount].to_i
    # VULNERABLE: Race between check and update
    if @@balance >= amount
      sleep(0.01)  # Simulates processing
      @@balance -= amount
      render json: { new_balance: @@balance }
    else
      render json: { error: 'Insufficient funds' }
    end
  end

  # Test 2: Double-checked locking
  @@instance = nil
  @@mutex = Mutex.new

  def get_singleton
    # VULNERABLE in Ruby without proper memory barriers
    if @@instance.nil?
      @@mutex.synchronize do
        if @@instance.nil?
          @@instance = Object.new
        end
      end
    end
    render json: { id: @@instance.object_id }
  end

  # Test 3: File TOCTOU
  def read_config
    filename = params[:filename]
    path = Rails.root.join('config', filename)
    # VULNERABLE: File can change between check and read
    if File.exist?(path)
      sleep(0.01)
      content = File.read(path)
      render plain: content
    else
      head :not_found
    end
  end

  # Test 4: Unsynchronized hash access
  @@cache = {}

  def add_to_cache
    key = params[:key]
    value = params[:value]
    # VULNERABLE: Hash not thread-safe
    unless @@cache.key?(key)
      @@cache[key] = value
    end
    head :ok
  end

  # Test 5: Session race condition
  def update_session
    # VULNERABLE: Session operations not atomic
    count = session[:count] || 0
    sleep(0.01)
    session[:count] = count + 1
    render json: { count: session[:count] }
  end

  # Test 6: Increment not atomic
  def increment_counter
    # VULNERABLE: += is not atomic
    @@counter += 1
    render json: { counter: @@counter }
  end

  # Test 7: Read-modify-write on model
  def update_inventory
    product = Product.find(params[:id])
    quantity = params[:quantity].to_i
    # VULNERABLE: Read-modify-write not atomic
    if product.stock >= quantity
      sleep(0.01)
      product.update(stock: product.stock - quantity)
      head :ok
    else
      render json: { error: 'Out of stock' }
    end
  end

  # Test 8: Optimistic locking bypass
  def update_record
    record = Record.find(params[:id])
    # VULNERABLE: No lock_version check
    record.update(data: params[:data])
    head :ok
  end

  # Test 9: Database race condition
  def create_unique
    email = params[:email]
    # VULNERABLE: Race between check and create
    unless User.exists?(email: email)
      User.create(email: email)
    end
    head :ok
  end

  # Test 10: File write race
  def write_file
    content = params[:content]
    path = Rails.root.join('data', 'shared.txt')
    # VULNERABLE: Concurrent writes can interleave
    File.open(path, 'a') do |f|
      f.write(content)
    end
    head :ok
  end

  # Test 11: Lazy initialization race
  @@config = nil

  def get_config
    # VULNERABLE: Multiple threads may initialize
    @@config ||= load_expensive_config
    render json: @@config
  end

  # Test 12: Thread-unsafe caching
  def cached_value
    # VULNERABLE: Rails.cache operations not atomic
    unless Rails.cache.exist?('expensive_value')
      value = compute_expensive_value
      Rails.cache.write('expensive_value', value)
    end
    render json: Rails.cache.read('expensive_value')
  end

  private

  def load_expensive_config
    { setting: 'value' }
  end

  def compute_expensive_value
    sleep(0.1)
    rand(1000)
  end
end
