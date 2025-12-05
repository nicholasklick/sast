<?php
// Mass Assignment vulnerabilities in PHP

class User {
    public $id;
    public $username;
    public $email;
    public $password;
    public $is_admin = false;  // Sensitive!
    public $balance = 0;       // Sensitive!
    public $role = 'user';     // Sensitive!
}

// Test 1: Direct property assignment from $_POST
function create_user_unsafe() {
    $user = new User();
    // VULNERABLE: All $_POST values assigned
    foreach ($_POST as $key => $value) {
        if (property_exists($user, $key)) {
            $user->$key = $value;
        }
    }
    return $user;
}

// Test 2: Using extract()
function create_with_extract() {
    $user = new User();
    // VULNERABLE: extract() creates variables from array
    extract($_POST);
    $user->username = $username ?? '';
    $user->email = $email ?? '';
    $user->is_admin = $is_admin ?? false;  // Oops!
    return $user;
}

// Test 3: Laravel-style mass assignment without $fillable
class UnsafeModel {
    public $attributes = [];

    public function fill($data) {
        // VULNERABLE: No attribute filtering
        foreach ($data as $key => $value) {
            $this->attributes[$key] = $value;
        }
        return $this;
    }
}

function create_laravel_style() {
    $model = new UnsafeModel();
    // VULNERABLE: All request data
    return $model->fill($_POST);
}

// Test 4: __set magic method
class MagicUser {
    private $data = [];

    public function __set($name, $value) {
        // VULNERABLE: No filtering
        $this->data[$name] = $value;
    }

    public function __get($name) {
        return $this->data[$name] ?? null;
    }
}

function create_magic_user() {
    $user = new MagicUser();
    // VULNERABLE: Any property can be set
    foreach ($_POST as $key => $value) {
        $user->$key = $value;
    }
    return $user;
}

// Test 5: array_merge with user data
function merge_user_data() {
    $defaults = ['role' => 'user', 'is_admin' => false];
    $user_data = $_POST;
    // VULNERABLE: User data overrides defaults
    return array_merge($defaults, $user_data);
}

// Test 6: Doctrine entity without protection
class DoctrineUser {
    private $id;
    private $username;
    private $email;
    private $isAdmin;

    public function fromArray($data) {
        // VULNERABLE: No field filtering
        foreach ($data as $key => $value) {
            $setter = 'set' . ucfirst($key);
            if (method_exists($this, $setter)) {
                $this->$setter($value);
            }
        }
    }

    public function setIsAdmin($value) {
        $this->isAdmin = $value;
    }
}

// Test 7: PDO insert with all fields
function insert_user_pdo() {
    $pdo = get_pdo();
    $fields = array_keys($_POST);
    $placeholders = array_map(fn($f) => ":$f", $fields);

    // VULNERABLE: Inserting all POST fields
    $sql = "INSERT INTO users (" . implode(',', $fields) . ") VALUES (" . implode(',', $placeholders) . ")";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($_POST);
}

// Test 8: JSON decode to object
function create_from_json() {
    $json = file_get_contents('php://input');
    // VULNERABLE: All JSON properties become object properties
    $user = json_decode($json);
    return $user;
}

// Test 9: Symfony form without field configuration
function handle_form() {
    // Pseudo-code for Symfony without proper form configuration
    $form = create_form(User::class);
    $form->submit($_POST);  // VULNERABLE: All fields submitted
    return $form->getData();
}

// Test 10: Yii2 model load
class Yii2User {
    public $username;
    public $email;
    public $is_admin;

    public function load($data) {
        // VULNERABLE: No safe attributes defined
        foreach ($data as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }
        return true;
    }
}

function get_pdo() {
    // Return PDO instance
    return new PDO('sqlite::memory:');
}

function create_form($class) {
    // Placeholder
    return new class {
        public function submit($data) {}
        public function getData() { return new User(); }
    };
}
?>
