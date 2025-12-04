// SQL Injection vulnerabilities in TypeScript
import { Connection } from 'mysql';
import { Pool } from 'pg';

class SqlInjectionVulnerabilities {
    private connection: Connection;
    private pool: Pool;

    getUserUnsafe(userId: string): Promise<any> {
        // VULNERABLE: String concatenation in SQL
        const query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return new Promise((resolve, reject) => {
            this.connection.query(query, (err, results) => {
                if (err) reject(err);
                resolve(results);
            });
        });
    }

    async loginUnsafe(username: string, password: string): Promise<boolean> {
        // VULNERABLE: Template literal SQL injection
        const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
        const result = await this.pool.query(sql);
        return result.rows.length > 0;
    }

    searchUnsafe(term: string): void {
        // VULNERABLE: SQL injection in search
        const query = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
        this.connection.query(query);
    }

    deleteUnsafe(tableName: string, id: number): void {
        // VULNERABLE: Table name injection
        const sql = `DELETE FROM ${tableName} WHERE id = ${id}`;
        this.connection.query(sql);
    }

    executeRaw(query: string): void {
        // VULNERABLE: Direct query execution
        this.connection.query(query);
    }
}

export { SqlInjectionVulnerabilities };
