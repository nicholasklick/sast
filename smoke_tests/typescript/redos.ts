// ReDoS (Regular Expression Denial of Service) Test Cases

// Test 1: Catastrophic backtracking with nested quantifiers
function validateEmail(email: string): boolean {
    // VULNERABLE: (a+)+ causes exponential backtracking
    const pattern = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-z]+$/;
    return pattern.test(email);
}

// Test 2: Multiple overlapping quantifiers
function validateInput(input: string): boolean {
    // VULNERABLE: (a*)*b pattern can cause ReDoS
    const pattern = /(a*)*b/;
    return pattern.test(input);
}

// Test 3: Alternation with overlapping patterns
function matchPattern(text: string): boolean {
    // VULNERABLE: (a|a)* causes catastrophic backtracking
    const pattern = /(a|a)*c/;
    return pattern.test(text);
}

// Test 4: Complex pattern with nested groups
function validateUsername(username: string): boolean {
    // VULNERABLE: (x+x+)+ causes exponential time complexity
    const pattern = /^(x+x+)+y$/;
    return pattern.test(username);
}

// Test 5: Greedy quantifiers with backtracking
function extractData(data: string): RegExpMatchArray | null {
    // VULNERABLE: Multiple greedy quantifiers can cause ReDoS
    const pattern = /(.*,)*(.*)$/;
    return data.match(pattern);
}
