
def check_user(user):
    # Use of assert for data validation
    assert user is not None, "User cannot be None"
    assert 'role' in user, "User must have a role"
    
    if user['role'] == 'admin':
        print("Admin user")
    else:
        print("Regular user")

# Asserts can be disabled with the -O flag, bypassing checks.
check_user({'role': 'guest'})
check_user(None)
