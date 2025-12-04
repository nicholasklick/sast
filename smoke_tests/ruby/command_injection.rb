# Command Injection vulnerabilities in Ruby

class CommandInjectionVulnerabilities
  def execute_command(user_input)
    # VULNERABLE: Command injection via system()
    system("ls #{user_input}")
  end

  def backtick_injection(filename)
    # VULNERABLE: Command injection via backticks
    `cat #{filename}`
  end

  def exec_injection(command)
    # VULNERABLE: Direct exec with user input
    exec(command)
  end

  def open_pipe(user_cmd)
    # VULNERABLE: Command injection via IO.popen
    IO.popen(user_cmd) { |io| io.read }
  end

  def spawn_command(arg)
    # VULNERABLE: spawn with user input
    spawn("sh -c '#{arg}'")
  end

  def percent_x(input)
    # VULNERABLE: %x operator injection
    %x(echo #{input})
  end

  def open_with_pipe(filename)
    # VULNERABLE: Open with pipe
    open("| cat #{filename}")
  end
end
