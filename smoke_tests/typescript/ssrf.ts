// SSRF vulnerabilities in TypeScript
import axios from 'axios';
import fetch from 'node-fetch';

class SsrfVulnerabilities {
    // VULNERABLE: User-controlled URL in fetch
    async fetchUserUrl(url: string): Promise<string> {
        const response = await fetch(url);
        return response.text();
    }

    // VULNERABLE: User-controlled URL in axios
    async axiosGet(endpoint: string): Promise<any> {
        const response = await axios.get(endpoint);
        return response.data;
    }

    // VULNERABLE: URL from query parameter
    async proxyRequest(targetUrl: string): Promise<Response> {
        return fetch(targetUrl);
    }

    // VULNERABLE: Internal service access
    async getInternalData(host: string, port: number): Promise<any> {
        const url = `http://${host}:${port}/internal/data`;
        return axios.get(url);
    }

    // VULNERABLE: File URL scheme
    async readLocalFile(path: string): Promise<string> {
        const response = await fetch(`file://${path}`);
        return response.text();
    }
}
