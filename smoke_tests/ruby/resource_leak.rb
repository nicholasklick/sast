# Resource Leak vulnerabilities in Ruby
require 'socket'
require 'net/http'

class ResourceLeakController < ApplicationController
  # Test 1: File not closed
  def read_file_unsafe
    path = params[:path]
    # VULNERABLE: File not closed on exception
    file = File.open(path, 'r')
    content = file.read
    # file.close might not be reached
    render plain: content
  end

  # Test 2: Socket not closed
  def connect_socket
    host = params[:host]
    port = params[:port].to_i
    # VULNERABLE: Socket leak
    socket = TCPSocket.new(host, port)
    data = socket.gets
    render plain: data
    # socket never closed
  end

  # Test 3: Database connection leak
  def query_database
    conn = PG.connect(dbname: 'mydb')
    # VULNERABLE: Connection not closed
    result = conn.exec('SELECT * FROM users')
    render json: result.to_a
    # conn never closed
  end

  # Test 4: Net::HTTP not properly closed
  def fetch_url_unsafe
    uri = URI(params[:url])
    # VULNERABLE: HTTP connection may leak
    http = Net::HTTP.new(uri.host, uri.port)
    http.start
    response = http.get(uri.path)
    render plain: response.body
    # http never finished
  end

  # Test 5: Early return leak
  def conditional_read
    path = params[:path]
    condition = params[:condition]
    file = File.open(path, 'r')
    if condition == 'skip'
      # VULNERABLE: Early return without close
      return head(:ok)
    end
    content = file.read
    file.close
    render plain: content
  end

  # Test 6: Exception path leak
  def process_file_unsafe
    file = File.open('/tmp/data.txt', 'r')
    begin
      process_content(file.read)
    rescue StandardError
      # VULNERABLE: File not closed in rescue
      raise
    end
    file.close
    head :ok
  end

  # Test 7: Tempfile not cleaned
  def create_temp
    # VULNERABLE: Tempfile not unlinked
    temp = Tempfile.new('data')
    temp.write(params[:data])
    temp.close
    # temp.unlink not called
    render plain: temp.path
  end

  # Test 8: Multiple resources not closed
  def multiple_files
    file1 = File.open('/tmp/a.txt', 'r')
    # VULNERABLE: If this fails, file1 leaks
    file2 = File.open('/tmp/b.txt', 'r')
    content = file1.read + file2.read
    file1.close
    file2.close
    render plain: content
  end

  # Test 9: Dir not closed
  def list_directory
    path = params[:path]
    # VULNERABLE: Dir not closed
    dir = Dir.open(path)
    entries = dir.entries
    render json: entries
    # dir.close never called
  end

  # Test 10: IO.popen not closed
  def run_command
    command = params[:cmd]
    # VULNERABLE: IO not closed
    io = IO.popen(command)
    output = io.read
    render plain: output
    # io.close never called
  end

  # Test 11: StringIO in loop
  def process_items
    params[:items].each do |item|
      # VULNERABLE: Many StringIO objects created
      io = StringIO.new
      io.write(item)
      # io never closed
    end
    head :ok
  end

  # Test 12: Gzip stream leak
  def read_gzip
    path = params[:path]
    gz = Zlib::GzipReader.open(path)
    content = gz.read
    # VULNERABLE: gz.close never called
    render plain: content
  end

  private

  def process_content(content)
    raise 'Error' if content.empty?
  end
end
