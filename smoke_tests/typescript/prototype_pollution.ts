// Prototype Pollution Test Cases

// Test 1: Unsafe object merge
function mergeObjects(target: any, source: any): any {
    // VULNERABLE: No prototype pollution protection
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// Test 2: Deep merge without protection
function deepMerge(target: any, source: any): any {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            // VULNERABLE: Recursive merge allows __proto__ pollution
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Test 3: Setting properties from user input
function setUserPreferences(user: any, preferences: any): void {
    // VULNERABLE: Direct property assignment from user input
    for (let key in preferences) {
        user[key] = preferences[key];
    }
}

// Test 4: Lodash-style set without sanitization
function setValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        // VULNERABLE: Can traverse to __proto__ or constructor
        current[keys[i]] = current[keys[i]] || {};
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;
}

// Test 5: JSON parse and merge
function updateConfigFromJSON(config: any, jsonString: string): any {
    const updates = JSON.parse(jsonString);
    // VULNERABLE: Merging parsed JSON without validation
    return Object.assign(config, updates);
}
