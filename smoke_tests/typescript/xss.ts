// XSS vulnerabilities in TypeScript
import { Request, Response } from 'express';

class XssVulnerabilities {
    reflectedXss(req: Request, res: Response): void {
        // VULNERABLE: Reflected XSS
        const name = req.query.name;
        res.send(`<h1>Hello ${name}</h1>`);
    }

    innerHtmlXss(userInput: string): void {
        // VULNERABLE: innerHTML assignment
        const element = document.getElementById('output');
        if (element) {
            element.innerHTML = userInput;
        }
    }

    documentWriteXss(data: string): void {
        // VULNERABLE: document.write
        document.write(data);
    }

    dangerouslySetInnerHTML(content: string): object {
        // VULNERABLE: React dangerouslySetInnerHTML
        return {
            __html: content
        };
    }

    templateInjection(template: string, data: any): string {
        // VULNERABLE: Template injection
        return eval('`' + template + '`');
    }

    jqueryHtml(userContent: string): void {
        // VULNERABLE: jQuery html()
        // @ts-ignore
        $('#output').html(userContent);
    }
}

export { XssVulnerabilities };
