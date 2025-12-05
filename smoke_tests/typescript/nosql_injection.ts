// NoSQL Injection Test Cases

// Test 1: MongoDB query with unsanitized input
async function findUserByUsername(db: any, username: string): Promise<any> {
    // VULNERABLE: Direct object injection in MongoDB query
    return await db.collection('users').findOne({ username: username });
}

// Test 2: MongoDB query with JSON parse
async function findUserWithFilter(db: any, filterJson: string): Promise<any> {
    // VULNERABLE: Parsing user input as query filter
    const filter = JSON.parse(filterJson);
    return await db.collection('users').findOne(filter);
}

// Test 3: MongoDB $where operator with user input
async function searchUsers(db: any, searchCriteria: string): Promise<any[]> {
    // VULNERABLE: $where executes JavaScript
    return await db.collection('users').find({ $where: searchCriteria }).toArray();
}

// Test 4: MongoDB aggregation with user input
async function aggregateWithUserPipeline(db: any, pipelineJson: string): Promise<any[]> {
    // VULNERABLE: User-controlled aggregation pipeline
    const pipeline = JSON.parse(pipelineJson);
    return await db.collection('orders').aggregate(pipeline).toArray();
}

// Test 5: Direct object property access in query
async function loginUser(db: any, credentials: any): Promise<any> {
    // VULNERABLE: credentials object could contain $ne, $gt, etc.
    return await db.collection('users').findOne({
        username: credentials.username,
        password: credentials.password
    });
}
