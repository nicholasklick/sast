<?php
// Insecure Deserialization vulnerabilities in PHP

class DeserializationVulnerabilities {
    public function unserializeUnsafe($data) {
        // VULNERABLE: unserialize with user input
        return unserialize($data);
    }

    public function unserializeBase64($encoded) {
        // VULNERABLE: unserialize after base64 decode
        $data = base64_decode($encoded);
        return unserialize($data);
    }

    public function unserializeCookie() {
        // VULNERABLE: unserialize from cookie
        if (isset($_COOKIE['user_data'])) {
            return unserialize($_COOKIE['user_data']);
        }
        return null;
    }

    public function evalCode($code) {
        // VULNERABLE: eval with user input
        return eval($code);
    }

    public function createFunction($args, $code) {
        // VULNERABLE: create_function with user input
        $func = create_function($args, $code);
        return $func;
    }

    public function pregReplaceEval($pattern, $replacement, $subject) {
        // VULNERABLE: preg_replace with /e modifier (deprecated)
        return preg_replace($pattern . 'e', $replacement, $subject);
    }

    public function assertCode($code) {
        // VULNERABLE: assert with user input
        assert($code);
    }
}
