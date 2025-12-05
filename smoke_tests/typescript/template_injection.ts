// Template Injection Test Cases

// Test 1: Server-Side Template Injection with Handlebars
function renderHandlebarsTemplate(userInput: string): string {
    const Handlebars = require('handlebars');
    // VULNERABLE: Compiling user input as template
    const template = Handlebars.compile(userInput);
    return template({});
}

// Test 2: Pug/Jade template injection
function renderPugTemplate(templateString: string, data: any): string {
    const pug = require('pug');
    // VULNERABLE: User-controlled template string
    const compiledFunction = pug.compile(templateString);
    return compiledFunction(data);
}

// Test 3: EJS template injection
function renderEJSTemplate(userTemplate: string, context: any): string {
    const ejs = require('ejs');
    // VULNERABLE: Rendering user-provided template
    return ejs.render(userTemplate, context);
}

// Test 4: Template literal with user input (client-side)
function generateHTML(userName: string, userBio: string): string {
    // VULNERABLE: If userName contains ${...}, it could execute code
    const template = `<div>Name: ${userName}, Bio: ${userBio}</div>`;
    return eval('`' + template + '`');
}

// Test 5: Lodash template injection
function renderLodashTemplate(templateStr: string, data: any): string {
    const _ = require('lodash');
    // VULNERABLE: User-controlled template
    const compiled = _.template(templateStr);
    return compiled(data);
}
