
const AdmZip = require('adm-zip');
const express = require('express');
const app = express();

app.post('/unzip', (req, res) => {
    const zipFile = req.files.zip;
    const zip = new AdmZip(zipFile.data);
    // Vulnerable to Zip Slip
    zip.extractAllTo('/unzipped-files/', true);
    res.send('File unzipped');
});

app.listen(3000);
