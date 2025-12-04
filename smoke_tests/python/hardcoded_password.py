
import os

def connect_to_db():
    # Hardcoded password
    password = "mysecretpassword123"
    db_host = os.environ.get("DB_HOST")
    # ... connection logic ...
    return f"Connecting with password: {password}"

connect_to_db()
