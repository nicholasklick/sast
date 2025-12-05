// File Upload vulnerabilities in JavaScript/Node.js
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');

// Test 1: No file type validation
const unsafeStorage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        // VULNERABLE: Original filename preserved
        cb(null, file.originalname);
    }
});

const unsafeUpload = multer({ storage: unsafeStorage });

function uploadNoValidation(req, res) {
    // VULNERABLE: No file type checking
    res.json({ filename: req.file.filename });
}

// Test 2: Extension-only validation
const extStorage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        // VULNERABLE: Can bypass with double extension
        if (['.jpg', '.png', '.gif'].includes(ext)) {
            cb(null, file.originalname);
        } else {
            cb(new Error('Invalid file type'));
        }
    }
});

// Test 3: MIME type only validation
const mimeFilter = (req, file, cb) => {
    // VULNERABLE: MIME type can be spoofed
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

const mimeUpload = multer({ fileFilter: mimeFilter });

// Test 4: Path traversal in filename
function uploadWithPath(req, res) {
    const file = req.file;
    // VULNERABLE: Filename can contain ../
    const destination = path.join('./uploads/', file.originalname);
    fs.renameSync(file.path, destination);
    res.json({ path: destination });
}

// Test 5: Upload to web root
function uploadToPublic(req, res) {
    const file = req.file;
    // VULNERABLE: Can upload to public directory
    const destination = path.join('./public/', file.originalname);
    fs.renameSync(file.path, destination);
    res.json({ path: destination });
}

// Test 6: No file size limit
const noLimitUpload = multer({
    storage: unsafeStorage,
    // VULNERABLE: No size limit - DoS possible
});

// Test 7: ZIP extraction without validation
function extractZip(req, res) {
    const zipPath = req.file.path;
    const extractPath = './extracted/';

    // VULNERABLE: No decompression bomb protection
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractPath, true);
    res.json({ extracted: true });
}

// Test 8: SVG upload (XSS)
function uploadSvg(req, res) {
    const file = req.file;
    const ext = path.extname(file.originalname).toLowerCase();
    // VULNERABLE: SVG can contain JavaScript
    if (ext === '.svg') {
        const destination = path.join('./images/', file.originalname);
        fs.renameSync(file.path, destination);
    }
    res.json({ filename: file.originalname });
}

// Test 9: Blacklist validation
const blacklistFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const blocked = ['.exe', '.dll', '.bat', '.sh'];
    // VULNERABLE: Blacklist incomplete (.js, .html allowed)
    if (!blocked.includes(ext)) {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

// Test 10: Race condition in upload
function uploadWithCheck(req, res) {
    const file = req.file;
    const destination = path.join('./uploads/', file.originalname);

    // VULNERABLE: TOCTOU race condition
    if (!fs.existsSync(destination)) {
        fs.renameSync(file.path, destination);
    }
    res.json({ filename: file.originalname });
}

// Test 11: File content not validated
function uploadContent(req, res) {
    const file = req.file;
    // VULNERABLE: Only checking extension, not content
    if (file.originalname.endsWith('.jpg')) {
        // No magic bytes validation
        fs.renameSync(file.path, './images/' + file.originalname);
    }
    res.json({ filename: file.originalname });
}

// Test 12: HTML upload
function uploadHtml(req, res) {
    const file = req.file;
    // VULNERABLE: HTML files can execute JavaScript
    const destination = path.join('./public/uploads/', file.originalname);
    fs.renameSync(file.path, destination);
    res.json({ url: '/uploads/' + file.originalname });
}

module.exports = {
    unsafeUpload,
    uploadNoValidation,
    uploadWithPath,
    uploadToPublic,
    extractZip,
    uploadSvg,
    uploadWithCheck,
    uploadContent,
    uploadHtml
};
