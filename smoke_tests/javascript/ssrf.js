const http = require('http');
const url = require('url');

// Simulate a user-provided URL from a query parameter
const userUrl = 'http://127.0.0.1/admin-status';
// const userUrl = 'http://169.254.169.254/latest/meta-data/'; // Cloud metadata endpoint

const options = url.parse(userUrl);

// --- VULNERABLE CODE ---
// The application makes a request to a URL fully or partially controlled by the user
http.get(options, (res) => { // CWE-918: Server-Side Request Forgery (SSRF)
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  res.on('end', () => {
    console.log('Response from internal service:', data);
  });
}).on('error', (err) => {
  console.error('Error making request:', err.message);
});
// -----------------------