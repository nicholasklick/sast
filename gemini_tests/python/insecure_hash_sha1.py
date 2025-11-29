
import hashlib

def hash_password(password):
    # Use of weak hashing algorithm SHA1
    return hashlib.sha1(password.encode()).hexdigest()

print(hash_password("another-weak-password"))
