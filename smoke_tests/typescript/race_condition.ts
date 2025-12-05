// Race Condition Test Cases

import * as fs from 'fs';

// Test 1: Check-then-use file operation
function readFileIfExists(filePath: string): string | null {
    // VULNERABLE: File could be deleted/modified between check and read
    if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8');
    }
    return null;
}

// Test 2: Non-atomic balance check and update
let accountBalance = 1000;

function withdraw(amount: number): boolean {
    // VULNERABLE: Balance could change between check and update
    if (accountBalance >= amount) {
        // Simulating some processing time
        accountBalance -= amount;
        return true;
    }
    return false;
}

// Test 3: File creation race
function createUniqueFile(basePath: string): string {
    let counter = 0;
    let filePath = `${basePath}-${counter}.txt`;
    // VULNERABLE: File could be created between exists check and creation
    while (fs.existsSync(filePath)) {
        counter++;
        filePath = `${basePath}-${counter}.txt`;
    }
    fs.writeFileSync(filePath, 'data');
    return filePath;
}

// Test 4: Shared resource without locking
class SharedCounter {
    private count = 0;

    increment(): void {
        // VULNERABLE: Read-modify-write is not atomic
        const currentValue = this.count;
        this.count = currentValue + 1;
    }

    getCount(): number {
        return this.count;
    }
}

// Test 5: Temp file creation vulnerability
function createTempFile(data: string): string {
    const tempPath = `/tmp/tempfile-${Date.now()}.txt`;
    // VULNERABLE: Predictable filename + race between check and create
    if (!fs.existsSync(tempPath)) {
        fs.writeFileSync(tempPath, data);
    }
    return tempPath;
}
