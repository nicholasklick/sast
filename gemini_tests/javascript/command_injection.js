const { exec } = require('child_process');

// Simulate user input from a web request
const userInput = "8.8.8.8; echo 'pwned by command injection'";

// --- VULNERABLE CODE ---
// Using exec with untrusted input is dangerous
const command = `ping -c 1 ${userInput}`;
exec(command, (error, stdout, stderr) => { // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
});
// -----------------------