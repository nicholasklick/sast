# Unsafe Execution vulnerabilities in Ruby
class UnsafeExecController < ApplicationController
  # Test 1: system with user input
  def run_system
    command = params[:command]
    # VULNERABLE: Direct command execution
    system(command)
    head :ok
  end

  # Test 2: exec with user input
  def run_exec
    program = params[:program]
    # VULNERABLE: exec with user input
    exec(program)
  end

  # Test 3: backticks with user input
  def run_backticks
    cmd = params[:cmd]
    # VULNERABLE: Command substitution
    output = `#{cmd}`
    render plain: output
  end

  # Test 4: %x{} with user input
  def run_percent_x
    cmd = params[:cmd]
    # VULNERABLE: %x{} is like backticks
    output = %x{#{cmd}}
    render plain: output
  end

  # Test 5: IO.popen with user input
  def run_popen
    command = params[:command]
    # VULNERABLE: Process spawning
    output = IO.popen(command) { |io| io.read }
    render plain: output
  end

  # Test 6: Open3.capture3 with user input
  def run_open3
    cmd = params[:cmd]
    # VULNERABLE: Open3 with user input
    stdout, stderr, status = Open3.capture3(cmd)
    render json: { stdout: stdout, stderr: stderr }
  end

  # Test 7: Kernel.spawn with user input
  def run_spawn
    command = params[:command]
    # VULNERABLE: Spawning process
    pid = spawn(command)
    Process.wait(pid)
    head :ok
  end

  # Test 8: PTY.spawn with user input
  def run_pty
    command = params[:command]
    # VULNERABLE: PTY spawn
    PTY.spawn(command) do |stdout, stdin, pid|
      output = stdout.read
      render plain: output
    end
  end

  # Test 9: Shell expansion in filename
  def read_file_shell
    filename = params[:filename]
    # VULNERABLE: Shell expansion
    output = `cat #{filename}`
    render plain: output
  end

  # Test 10: Shellwords.escape bypass
  def escaped_command
    input = params[:input]
    # VULNERABLE: Escaping may be bypassed
    safe_input = Shellwords.escape(input)
    output = `echo #{safe_input}`  # Still risky patterns
    render plain: output
  end

  # Test 11: Process.spawn with shell
  def spawn_shell
    args = params[:args]
    # VULNERABLE: Shell: true enables command injection
    pid = Process.spawn("echo #{args}", shell: true)
    Process.wait(pid)
    head :ok
  end

  # Test 12: Fork + exec pattern
  def fork_exec
    command = params[:command]
    # VULNERABLE: Fork then exec
    pid = fork do
      exec(command)
    end
    Process.wait(pid)
    head :ok
  end

  # Test 13: Kernel.` (backtick method)
  def kernel_backtick
    cmd = params[:cmd]
    # VULNERABLE: Kernel method
    output = Kernel.`(cmd)
    render plain: output
  end

  # Test 14: send with system
  def dynamic_exec
    method = params[:method]  # Could be 'system'
    cmd = params[:cmd]
    # VULNERABLE: Dynamic method call
    Kernel.send(method, cmd)
    head :ok
  end
end
