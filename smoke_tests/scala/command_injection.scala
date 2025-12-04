// Command Injection vulnerabilities in Scala
import scala.sys.process._

class CommandInjectionVulnerabilities {
  def executeCommand(userInput: String): String = {
    // VULNERABLE: Command injection via Process
    s"ls $userInput".!!
  }

  def runShellCommand(command: String): String = {
    // VULNERABLE: Shell command execution
    Process(Seq("sh", "-c", command)).!!
  }

  def pingHost(host: String): String = {
    // VULNERABLE: Command injection in ping
    s"ping -c 1 $host".!!
  }

  def catFile(filename: String): String = {
    // VULNERABLE: Command injection via cat
    s"cat $filename".!!
  }

  def executeScript(scriptPath: String): Int = {
    // VULNERABLE: Arbitrary script execution
    s"bash $scriptPath".!
  }

  def grepLogs(pattern: String): String = {
    // VULNERABLE: Command injection in grep
    s"grep $pattern /var/log/app.log".!!
  }

  def processBuilderInjection(cmd: String): String = {
    // VULNERABLE: ProcessBuilder with user input
    Process(cmd).!!
  }
}
