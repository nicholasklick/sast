// Comprehensive test file for all security queries
// This file contains examples of various vulnerability patterns

// ===== SQL Injection =====
function sqlInjection(userId: string) {
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    execute(query);
}

// ===== Command Injection =====
function commandInjection(filename: string) {
    exec(`cat ${filename}`);
}

// ===== XSS (Cross-Site Scripting) =====
function xssVulnerability(userContent: string) {
    document.getElementById('content').innerHTML = userContent;
}

// ===== Path Traversal =====
function pathTraversal(userPath: string) {
    const fs = require('fs');
    fs.readFile(`/app/uploads/${userPath}`, 'utf8', callback);
    fs.writeFile(`./data/${userPath}`, data);
}

function requireTraversal(moduleName: string) {
    const module = require(moduleName);
}

// ===== Hardcoded Secrets =====
const API_KEY = "sk-1234567890abcdef";
const database_password = "mysecretpassword123";
const auth_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const private_key = "-----BEGIN RSA PRIVATE KEY-----";

// ===== Insecure Deserialization =====
function insecureDeserialize(data: string) {
    const obj = eval(data);
    return obj;
}

function pickleLoads(serialized: any) {
    const pickle = require('pickle');
    return pickle.loads(serialized);
}

function yamlUnsafe(input: string) {
    const yaml = require('js-yaml');
    return yaml.unsafe_load(input);
}

// ===== XXE (XML External Entity) =====
function parseXmlUnsafe(xmlData: string) {
    const parser = new DOMParser();
    const doc = parser.parseXml(xmlData);
    return doc;
}

function xmlParserVuln(input: string) {
    const xml = require('xml2js');
    xml.parse(input, callback);
}

// ===== SSRF (Server-Side Request Forgery) =====
function ssrfVulnerability(url: string) {
    fetch(url).then(res => res.json());
}

function axiosSSRF(targetUrl: string) {
    axios.get(targetUrl).then(response => {
        console.log(response.data);
    });
}

function requestSSRF(endpoint: string) {
    request(endpoint, callback);
}

// ===== Weak Cryptography =====
function weakCrypto(data: string) {
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(data).digest('hex');
    return hash;
}

function sha1Hash(input: string) {
    const crypto = require('crypto');
    return crypto.createHash('sha1').update(input).digest();
}

function desEncryption(plaintext: string, key: string) {
    const crypto = require('crypto');
    const cipher = crypto.createCipher('des', key);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// ===== LDAP Injection =====
function ldapInjection(username: string) {
    const ldap = require('ldapjs');
    const filter = `(uid=${username})`;
    ldap.search('ou=users,dc=example,dc=com', { filter }, callback);
}

// ===== Unsafe Redirect =====
function unsafeRedirect(targetUrl: string) {
    response.redirect(targetUrl);
}

function sendRedirectVuln(location: string) {
    response.sendRedirect(location);
}

// ===== Template Injection =====
function templateInjection(userTemplate: string) {
    const ejs = require('ejs');
    const rendered = ejs.render(userTemplate, { data: 'value' });
    return rendered;
}

function handlebarsRender(template: string, data: any) {
    const handlebars = require('handlebars');
    const compiledTemplate = handlebars.compile(template);
    return compiledTemplate(data);
}

// ===== Multiple vulnerabilities in one function =====
function multipleVulns(userId: string, targetUrl: string) {
    // SQL Injection
    execute(`SELECT * FROM users WHERE id = '${userId}'`);

    // SSRF
    fetch(targetUrl);

    // Weak crypto
    const crypto = require('crypto');
    const hash = crypto.createHash('md5').update(userId).digest('hex');
}
