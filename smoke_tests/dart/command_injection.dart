// Command Injection vulnerabilities in Dart

import 'dart:io';

// Test 1: Process.run with user input
Future<void> vulnerableProcessRun(String userCommand) async {
  // VULNERABLE: Direct command execution
  await Process.run(userCommand, []);
}

// Test 2: Process.run with arguments
Future<void> vulnerableProcessRunArgs(String arg) async {
  // VULNERABLE: User input in arguments
  await Process.run('ls', [arg]);
}

// Test 3: Process.runSync with user input
void vulnerableProcessRunSync(String command) {
  // VULNERABLE: Synchronous command execution
  Process.runSync(command, []);
}

// Test 4: Process.start with user input
Future<void> vulnerableProcessStart(String command) async {
  // VULNERABLE: Starting process with user input
  await Process.start(command, []);
}

// Test 5: Shell command with string interpolation
Future<void> vulnerableShellCommand(String filename) async {
  // VULNERABLE: Shell injection via interpolation
  await Process.run('sh', ['-c', 'cat $filename']);
}

// Test 6: Command from environment variable
Future<void> vulnerableEnvCommand() async {
  // VULNERABLE: Command from environment
  var cmd = Platform.environment['COMMAND'];
  if (cmd != null) {
    await Process.run(cmd, []);
  }
}

// Test 7: Command from file
Future<void> vulnerableFileCommand(String configPath) async {
  // VULNERABLE: Command read from file
  var file = File(configPath);
  var command = await file.readAsString();
  await Process.run(command.trim(), []);
}

// Test 8: Command from HTTP request
Future<void> vulnerableHttpCommand(String url) async {
  // VULNERABLE: Command from network
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  var command = await response.transform(utf8.decoder).join();
  await Process.run(command, []);
}

// Test 9: Multiple commands via shell
Future<void> vulnerableMultipleCommands(String cmd1, String cmd2) async {
  // VULNERABLE: Command chaining
  await Process.run('sh', ['-c', '$cmd1 && $cmd2']);
}

// Test 10: Command with pipe
Future<void> vulnerablePipeCommand(String pattern) async {
  // VULNERABLE: Pipe injection
  await Process.run('sh', ['-c', 'cat /etc/passwd | grep $pattern']);
}

// Test 11: Backtick-style command substitution
Future<void> vulnerableCommandSubstitution(String input) async {
  // VULNERABLE: Command substitution
  await Process.run('sh', ['-c', 'echo \$(cat $input)']);
}

// Test 12: Process with working directory from user
Future<void> vulnerableWorkingDir(String dir, String cmd) async {
  // VULNERABLE: User-controlled working directory
  await Process.run(cmd, [], workingDirectory: dir);
}

// Test 13: Command from stdin
Future<void> vulnerableStdinCommand() async {
  // VULNERABLE: Command from standard input
  stdout.write('Enter command: ');
  var command = stdin.readLineSync();
  if (command != null) {
    await Process.run(command, []);
  }
}

// Test 14: Process with user-controlled environment
Future<void> vulnerableEnvInjection(String envVar, String value) async {
  // VULNERABLE: Environment injection
  await Process.run('printenv', [], environment: {envVar: value});
}

// Test 15: Dynamic executable path
Future<void> vulnerableDynamicPath(String execName) async {
  // VULNERABLE: User-controlled executable path
  await Process.run('/usr/bin/$execName', []);
}
