
import hashlib

def hash_password(password):
    # Use of weak hashing algorithm MD5
    return hashlib.md5(password.encode()).hexdigest()

print(hash_password("my-super-secret-password"))
