// NoSQL Injection Test Cases

use mongodb::bson::{doc, Document};

// Test 1: MongoDB query with unsanitized input
async fn find_user_by_username(username: &str) -> Result<Option<Document>, mongodb::error::Error> {
    use mongodb::Client;

    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("myapp");
    let collection = db.collection::<Document>("users");

    // VULNERABLE: Direct string interpolation in query
    let filter = doc! { "username": username };
    collection.find_one(filter, None).await
}

// Test 2: MongoDB $where operator with user input
async fn search_users_where(criteria: &str) -> Result<Vec<Document>, mongodb::error::Error> {
    use mongodb::Client;

    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("myapp");
    let collection = db.collection::<Document>("users");

    // VULNERABLE: $where executes JavaScript
    let filter = doc! { "$where": criteria };
    let cursor = collection.find(filter, None).await?;
    Ok(vec![]) // Simplified
}

// Test 3: Dynamic field injection
async fn find_by_field(field_name: &str, value: &str) -> Result<Option<Document>, mongodb::error::Error> {
    use mongodb::Client;

    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("myapp");
    let collection = db.collection::<Document>("users");

    // VULNERABLE: User-controlled field name
    let filter = doc! { field_name: value };
    collection.find_one(filter, None).await
}

// Test 4: Aggregation pipeline from user input
async fn aggregate_with_user_pipeline(pipeline_json: &str) -> Result<Vec<Document>, Box<dyn std::error::Error>> {
    use mongodb::Client;

    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("myapp");
    let collection = db.collection::<Document>("orders");

    // VULNERABLE: User-controlled aggregation pipeline
    let pipeline: Vec<Document> = serde_json::from_str(pipeline_json)?;
    let cursor = collection.aggregate(pipeline, None).await?;
    Ok(vec![]) // Simplified
}

// Test 5: Login bypass vulnerability
async fn login_user(username: &str, password: &str) -> Result<Option<Document>, mongodb::error::Error> {
    use mongodb::Client;

    let client = Client::with_uri_str("mongodb://localhost:27017").await?;
    let db = client.database("myapp");
    let collection = db.collection::<Document>("users");

    // VULNERABLE: Could pass {"$ne": ""} to bypass authentication
    let filter = doc! {
        "username": username,
        "password": password
    };
    collection.find_one(filter, None).await
}
