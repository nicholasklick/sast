// XPath Injection Test Cases

// Test 1: XPath query with unsanitized user input
function findUserByName(xmlDoc: any, username: string): any {
    // VULNERABLE: username could contain XPath injection like ' or '1'='1
    const xpath = `//users/user[username/text()='${username}']`;
    return xmlDoc.evaluate(xpath);
}

// Test 2: Authentication using XPath
function authenticateWithXPath(xmlDoc: any, user: string, pass: string): boolean {
    // VULNERABLE: user could be "admin' or '1'='1" to bypass authentication
    const xpath = `//user[username='${user}' and password='${pass}']`;
    const result = xmlDoc.evaluate(xpath);
    return result.length > 0;
}

// Test 3: XPath query with multiple user inputs
function searchProducts(xmlDoc: any, category: string, minPrice: string): any {
    // VULNERABLE: Both category and minPrice are unsanitized
    const xpath = `//products/product[category='${category}' and price>=${minPrice}]`;
    return xmlDoc.evaluate(xpath);
}

// Test 4: XPath contains function with user input
function searchByPartialMatch(xmlDoc: any, searchTerm: string): any {
    // VULNERABLE: searchTerm could break out of the contains function
    const xpath = `//item[contains(name, '${searchTerm}')]`;
    return xmlDoc.evaluate(xpath);
}

// Test 5: Complex XPath with user-controlled predicate
function customXPathQuery(xmlDoc: any, field: string, value: string): any {
    // VULNERABLE: field and value allow arbitrary XPath construction
    const xpath = `//${field}[text()='${value}']`;
    return xmlDoc.evaluate(xpath);
}
