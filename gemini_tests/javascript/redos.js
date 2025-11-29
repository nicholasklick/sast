
const re = new RegExp('(a+)+');
const str = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaab';
// Potential for ReDoS
re.test(str);
