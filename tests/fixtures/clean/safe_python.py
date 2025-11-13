"""Clean Python file with no vulnerabilities"""

import hashlib
from typing import List


def calculate_hash(data: str) -> str:
    """Safely hash data using modern algorithm"""
    # Using SHA-256 instead of weak MD5
    return hashlib.sha256(data.encode()).hexdigest()


def process_user_input(user_input: str) -> str:
    """Properly sanitize user input"""
    # Remove dangerous characters
    sanitized = user_input.replace('<', '&lt;').replace('>', '&gt;')
    return sanitized


def execute_safe_query(user_id: int) -> dict:
    """Use parameterized query"""
    # Using parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))


def safe_file_operation(filename: str) -> str:
    """Validate file path to prevent traversal"""
    import os

    # Validate that filename doesn't contain path traversal
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Invalid filename")

    # Construct safe path
    safe_path = os.path.join('/safe/directory', os.path.basename(filename))

    with open(safe_path, 'r') as f:
        return f.read()
