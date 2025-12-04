
// This is a common pattern in Node.js, but can be problematic
process.on('uncaughtException', (err) => {
  console.log('Caught exception: ' + err);
  // Not exiting the process can leave it in an inconsistent state
});
