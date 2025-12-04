// Path Traversal vulnerabilities in TypeScript
import * as fs from 'fs';
import * as path from 'path';
import { Request, Response } from 'express';

class PathTraversalVulnerabilities {
    readFileUnsafe(filename: string): string {
        // VULNERABLE: Path traversal via concatenation
        const filePath = `/var/data/${filename}`;
        return fs.readFileSync(filePath, 'utf8');
    }

    serveFileUnsafe(req: Request, res: Response): void {
        // VULNERABLE: No path validation
        const userPath = req.query.file as string;
        const fullPath = path.join('/public/files', userPath);
        res.sendFile(fullPath);
    }

    deleteFileUnsafe(filename: string): void {
        // VULNERABLE: Arbitrary file deletion
        const filePath = `/tmp/${filename}`;
        fs.unlinkSync(filePath);
    }

    writeFileUnsafe(filename: string, content: string): void {
        // VULNERABLE: User controls path
        const filePath = `/uploads/${filename}`;
        fs.writeFileSync(filePath, content);
    }

    listDirectoryUnsafe(dirName: string): string[] {
        // VULNERABLE: Directory listing with user input
        const dirPath = `/data/${dirName}`;
        return fs.readdirSync(dirPath);
    }

    downloadFileUnsafe(req: Request, res: Response): void {
        // VULNERABLE: Direct path from user
        const file = req.params.filename;
        res.download('/downloads/' + file);
    }
}

export { PathTraversalVulnerabilities };
