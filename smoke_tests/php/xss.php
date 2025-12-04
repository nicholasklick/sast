<?php
// XSS vulnerabilities in PHP

class XssVulnerabilities {
    public function reflectedXss() {
        // VULNERABLE: Reflected XSS
        echo "<h1>Hello " . $_GET['name'] . "</h1>";
    }

    public function storedXss($content) {
        // VULNERABLE: Stored XSS - output without encoding
        echo $content;
    }

    public function printXss() {
        // VULNERABLE: print with user input
        print("Welcome " . $_POST['username']);
    }

    public function printfXss($data) {
        // VULNERABLE: printf with user input
        printf("<div>%s</div>", $data);
    }

    public function attributeXss($url) {
        // VULNERABLE: XSS in HTML attribute
        echo "<a href='" . $url . "'>Click here</a>";
    }

    public function javascriptXss($data) {
        // VULNERABLE: XSS in JavaScript context
        echo "<script>var data = '" . $data . "';</script>";
    }

    public function jsonXss($userData) {
        // VULNERABLE: XSS via JSON output
        header('Content-Type: application/json');
        echo json_encode(['data' => $userData]);
    }
}
