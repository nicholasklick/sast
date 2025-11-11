// Test interprocedural taint analysis
// This should detect taint flowing through multiple function calls

// Case 1: Taint flows through return value
function getTaintedData() {
    return getUserInput();
}

function useDataDirectly() {
    const data = getTaintedData();
    executeQuery(`SELECT * FROM users WHERE id='${data}'`);
}

// Case 2: Taint flows through parameter
function processInput(input: string) {
    executeQuery(`DELETE FROM users WHERE name='${input}'`);
}

function main() {
    const userInput = getUserInput();
    processInput(userInput);
}

// Case 3: Sanitization in called function
function sanitizeData(data: string): string {
    return escapeHtml(data);
}

function safeUsage() {
    const raw = getUserInput();
    const clean = sanitizeData(raw);
    executeQuery(`INSERT INTO logs VALUES ('${clean}')`);
}

// Case 4: Multi-hop taint flow
function step1() {
    return getUserInput();
}

function step2() {
    const data = step1();
    return data;
}

function step3() {
    const result = step2();
    executeQuery(`UPDATE users SET data='${result}'`);
}

// Case 5: Class methods
class DataProcessor {
    private data: string;

    loadData() {
        this.data = getUserInput();
    }

    saveData() {
        executeQuery(`INSERT INTO data VALUES ('${this.data}')`);
    }

    process() {
        this.loadData();
        this.saveData();  // Should detect taint from loadData to saveData
    }
}
