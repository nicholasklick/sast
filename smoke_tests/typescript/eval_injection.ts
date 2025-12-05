// Eval Injection Test Cases

// Test 1: Direct eval with user input
function calculateUserExpression(expression: string): number {
    // VULNERABLE: eval executes arbitrary code
    return eval(expression);
}

// Test 2: Function constructor with user input
function createDynamicFunction(userCode: string): Function {
    // VULNERABLE: Function constructor is similar to eval
    return new Function('x', userCode);
}

// Test 3: eval in setTimeout
function scheduleUserCode(code: string, delay: number): void {
    // VULNERABLE: setTimeout with string argument uses eval
    setTimeout(code, delay);
}

// Test 4: eval in setInterval
function repeatUserCode(code: string, interval: number): void {
    // VULNERABLE: setInterval with string argument uses eval
    setInterval(code, interval);
}

// Test 5: Indirect eval usage
function processFormula(formula: string, context: any): any {
    const evalFunc = eval;
    // VULNERABLE: Indirect eval still executes arbitrary code
    return evalFunc(`with(context) { ${formula} }`);
}
