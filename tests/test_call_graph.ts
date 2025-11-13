// Test file to demonstrate call graph capabilities

function main() {
    const user = getUserInput();
    const processed = processData(user);
    sendToDatabase(processed);
}

function getUserInput(): string {
    return readFromFile("input.txt");
}

function processData(data: string): string {
    return sanitize(data);
}

function sanitize(input: string): string {
    return escapeHtml(input);
}

function sendToDatabase(data: string) {
    executeQuery(`INSERT INTO data VALUES ('${data}')`);
}

class DataHandler {
    private db: Database;

    public process(input: string) {
        const clean = this.validate(input);
        this.store(clean);
    }

    private validate(data: string): string {
        return sanitize(data);
    }

    private store(data: string) {
        this.db.insert(data);
    }
}

// Complex call chain
function complexChain() {
    stepOne();
}

function stepOne() {
    stepTwo();
}

function stepTwo() {
    stepThree();
}

function stepThree() {
    console.log("done");
}
