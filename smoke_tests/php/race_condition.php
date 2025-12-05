<?php
// Race Condition vulnerabilities in PHP

// Test 1: Check-then-act on balance
function withdraw() {
    $amount = (int)$_POST['amount'];
    $user_id = $_SESSION['user_id'];

    $balance = get_balance($user_id);
    // VULNERABLE: Race between check and update
    if ($balance >= $amount) {
        usleep(10000);  // Simulates processing
        update_balance($user_id, $balance - $amount);
        echo json_encode(['new_balance' => $balance - $amount]);
    } else {
        echo json_encode(['error' => 'Insufficient funds']);
    }
}

// Test 2: File TOCTOU
function read_config() {
    $filename = $_GET['filename'];
    $path = "/config/$filename";

    // VULNERABLE: File can change between check and read
    if (file_exists($path)) {
        usleep(10000);
        $content = file_get_contents($path);
        echo $content;
    }
}

// Test 3: Coupon redemption race
function redeem_coupon() {
    $coupon_code = $_POST['code'];

    $coupon = get_coupon($coupon_code);
    // VULNERABLE: Race to redeem same coupon multiple times
    if ($coupon && !$coupon['used']) {
        apply_discount($coupon);
        mark_coupon_used($coupon_code);
        echo "Discount applied!";
    }
}

// Test 4: Session race condition
function update_cart() {
    session_start();
    // VULNERABLE: Session not locked during operation
    $cart = $_SESSION['cart'] ?? [];
    usleep(10000);
    $cart[] = $_POST['item'];
    $_SESSION['cart'] = $cart;
}

// Test 5: File write race
function write_log() {
    $content = $_POST['content'];
    $path = '/var/log/app.log';

    // VULNERABLE: Concurrent writes can interleave
    $f = fopen($path, 'a');
    fwrite($f, $content);
    fclose($f);
}

// Test 6: Counter increment race
function increment_counter() {
    $counter_file = '/tmp/counter.txt';

    // VULNERABLE: Non-atomic increment
    $count = (int)file_get_contents($counter_file);
    usleep(10000);
    file_put_contents($counter_file, $count + 1);
    echo $count + 1;
}

// Test 7: User registration race
function register_user() {
    $email = $_POST['email'];

    // VULNERABLE: Race between check and insert
    if (!user_exists($email)) {
        usleep(10000);
        create_user($email, $_POST['password']);
        echo "User created";
    }
}

// Test 8: File creation race
function create_unique_file() {
    $filename = $_GET['name'];
    $path = "/uploads/$filename";

    // VULNERABLE: TOCTOU race
    if (!file_exists($path)) {
        usleep(10000);
        file_put_contents($path, $_POST['content']);
    }
}

// Test 9: Lock file race
function acquire_lock() {
    $lock_file = '/tmp/app.lock';

    // VULNERABLE: Non-atomic lock check
    if (!file_exists($lock_file)) {
        touch($lock_file);
        // Do work
        unlink($lock_file);
    }
}

// Test 10: Database race (SELECT then UPDATE)
function update_stock() {
    $product_id = $_POST['product_id'];
    $quantity = (int)$_POST['quantity'];

    $pdo = get_pdo();
    // VULNERABLE: Race between SELECT and UPDATE
    $stmt = $pdo->prepare("SELECT stock FROM products WHERE id = ?");
    $stmt->execute([$product_id]);
    $stock = $stmt->fetchColumn();

    if ($stock >= $quantity) {
        usleep(10000);
        $stmt = $pdo->prepare("UPDATE products SET stock = stock - ? WHERE id = ?");
        $stmt->execute([$quantity, $product_id]);
    }
}

// Test 11: Directory creation race
function ensure_directory() {
    $dir = $_GET['dir'];
    $path = "/data/$dir";

    // VULNERABLE: Race condition
    if (!is_dir($path)) {
        mkdir($path, 0755, true);
    }
}

// Helper functions
function get_balance($user_id) { return 1000; }
function update_balance($user_id, $balance) {}
function get_coupon($code) { return ['used' => false]; }
function apply_discount($coupon) {}
function mark_coupon_used($code) {}
function user_exists($email) { return false; }
function create_user($email, $password) {}
function get_pdo() { return new PDO('sqlite::memory:'); }
?>
