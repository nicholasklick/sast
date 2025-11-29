
import random

def generate_token():
    # Insecure random number generator for security-sensitive context
    return ''.join(random.choice('abcdef0123456789') for _ in range(32))

print(f"Session token: {generate_token()}")
