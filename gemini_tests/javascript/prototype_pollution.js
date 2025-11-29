// A vulnerable recursive merge function
function recursiveMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__') {
      // This check is often missing in vulnerable code
      continue;
    }
    if (typeof target[key] === 'object' && typeof source[key] === 'object') {
      recursiveMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// --- VULNERABLE CODE ---
// A merge function that does not check for `__proto__`
function vulnerableMerge(target, source) {
    for (let key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            if (key in target && typeof target[key] === 'object' && typeof source[key] === 'object') {
                vulnerableMerge(target[key], source[key]);
            } else {
                target[key] = source[key]; // The vulnerability is here
            }
        }
    }
    return target;
}


// Simulate a malicious JSON payload from an attacker
const maliciousPayload = JSON.parse('{"__proto__": {"polluted": "Yes"}}');

let target = {};
vulnerableMerge(target, maliciousPayload); // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
// -----------------------

// Now, any new object will have the "polluted" property
const newObject = {};
if (newObject.polluted) {
  console.log(`Prototype pollution successful! newObject.polluted = ${newObject.polluted}`);
}