
const child_process = require('child_process');

// Spawning a shell is dangerous
child_process.spawn('bash', ['-c', 'ls']);
