<?php
// Path Traversal vulnerabilities in PHP

class PathTraversalVulnerabilities {
    public function readFileUnsafe($filename) {
        // VULNERABLE: Path traversal via concatenation
        $path = '/var/data/' . $filename;
        return file_get_contents($path);
    }

    public function includeFileUnsafe($page) {
        // VULNERABLE: LFI via include
        include('/templates/' . $page . '.php');
    }

    public function requireFileUnsafe($module) {
        // VULNERABLE: LFI via require
        require($module);
    }

    public function deleteFileUnsafe($filename) {
        // VULNERABLE: Arbitrary file deletion
        $path = '/tmp/' . $filename;
        unlink($path);
    }

    public function readFileUrl($url) {
        // VULNERABLE: Remote file inclusion
        return file_get_contents($url);
    }

    public function downloadFile() {
        // VULNERABLE: Path traversal in download
        $file = $_GET['file'];
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile('/downloads/' . $file);
    }

    public function writeFileUnsafe($filename, $content) {
        // VULNERABLE: Arbitrary file write
        file_put_contents('/uploads/' . $filename, $content);
    }
}
