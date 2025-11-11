// Test file for symbol table integration
function authenticate(username: string, password: string): boolean {
    const sanitized = escapeHtml(username);
    const query = `SELECT * FROM users WHERE username='${sanitized}'`;
    return executeQuery(query);
}

class UserService {
    private db: Database;

    public findUser(name: string): User {
        const tainted = getUserInput();
        const sql = `SELECT * FROM users WHERE name='${tainted}'`;
        return this.db.query(sql);
    }
}
