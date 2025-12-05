<?php
// Authorization vulnerabilities in PHP

// Test 1: Missing authorization check
function admin_dashboard() {
    // VULNERABLE: No authorization check
    $users = get_all_users();
    return render_dashboard($users);
}

// Test 2: IDOR - Insecure Direct Object Reference
function view_document() {
    $document_id = $_GET['id'];
    // VULNERABLE: No ownership check
    $document = get_document($document_id);
    return render_document($document);
}

// Test 3: Horizontal privilege escalation
function view_profile() {
    $user_id = $_GET['user_id'];
    // VULNERABLE: Can view any user's profile
    $profile = get_user_profile($user_id);
    return render_profile($profile);
}

// Test 4: Vertical privilege escalation
function delete_user() {
    $user_id = $_POST['user_id'];
    // VULNERABLE: No admin check
    delete_user_by_id($user_id);
    return redirect('/users');
}

// Test 5: Client-side authorization
function get_secret_data() {
    // VULNERABLE: Relying on JavaScript for authorization
    return json_encode(['secret' => 'sensitive data']);
}

// Test 6: Predictable resource IDs
function get_order() {
    $order_id = $_GET['id'];
    // VULNERABLE: Sequential IDs allow enumeration
    $order = get_order_by_id($order_id);
    echo json_encode($order);
}

// Test 7: Missing function level access control
function execute_function() {
    $function = $_GET['function'];
    // VULNERABLE: No permission check
    if (function_exists($function)) {
        return $function();
    }
}

// Test 8: Path-based authorization bypass
function admin_api() {
    $path = $_SERVER['REQUEST_URI'];
    // VULNERABLE: Can bypass with case or encoding
    if (stripos($path, '/admin') === 0) {
        return json_encode(['data' => 'admin data']);
    }
    http_response_code(401);
}

// Test 9: Check after action
function update_settings() {
    $settings = $_POST['settings'];
    // VULNERABLE: Action happens before authorization
    update_system_settings($settings);

    if (!is_admin()) {
        http_response_code(401);
        return;
    }
    return redirect('/settings');
}

// Test 10: Trusting user-provided role
function action_with_role() {
    $role = $_SERVER['HTTP_X_USER_ROLE'];
    // VULNERABLE: Trusting client header
    if ($role === 'admin') {
        return json_encode(['admin_data' => true]);
    }
    http_response_code(403);
}

// Test 11: Cached authorization
function cached_admin_page() {
    // VULNERABLE: Cached page served to non-admins
    header('Cache-Control: public, max-age=3600');
    return render_admin_page();
}

// Test 12: Incomplete authorization chain
function edit_post() {
    $post_id = $_POST['post_id'];
    $content = $_POST['content'];

    // VULNERABLE: Only checks if logged in, not ownership
    if (is_logged_in()) {
        update_post($post_id, $content);
        return redirect('/posts/' . $post_id);
    }
    http_response_code(401);
}

// Helper functions
function get_all_users() { return []; }
function render_dashboard($users) {}
function get_document($id) { return []; }
function render_document($doc) {}
function get_user_profile($id) { return []; }
function render_profile($profile) {}
function delete_user_by_id($id) {}
function redirect($url) { header("Location: $url"); }
function get_order_by_id($id) { return []; }
function update_system_settings($settings) {}
function is_admin() { return false; }
function is_logged_in() { return true; }
function render_admin_page() {}
function update_post($id, $content) {}
?>
