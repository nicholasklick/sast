import os
import subprocess

# Simulate user input from a web request or CLI
user_input = "example.com; echo 'pwned by command injection'"

# --- VULNERABLE CODE (os.system) ---
# Using os.system with untrusted input
command = f"ping -c 1 {user_input}"
os.system(command) # CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
# ------------------------------------

# --- VULNERABLE CODE (subprocess) ---
# Using subprocess with shell=True
subprocess.run(command, shell=True) # CWE-78
# ------------------------------------
