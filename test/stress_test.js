var tweetnacl_nodewrap = require('../nacl');
var tweetnacl_js = require('tweetnacl');

// Test tweetnacl_nodewrap
console.log('------Test for tweetnacl node-wrap------');
console.log(new Date().toISOString());
for (var i = 0; i < 1000; i++ ) {
	tweetnacl_nodewrap.sign.keyPair();
}
console.log(new Date().toISOString());

// test tweetnacl js
console.log('------Test for tweetnacl js------');
console.log(new Date().toISOString());
for (var i = 0; i < 1000; i++ ) {
	tweetnacl_js.sign.keyPair();
}
console.log(new Date().toISOString());
