var nacl = require('../src/js/nacl.js');
var test = require('tape');

var randomVectors = require('./data/box.random');

var enc = nacl.util.encodeBase64,
    dec = nacl.util.decodeBase64;

module.exports = function() {
  test('nacl.box random test vectors', function(t) {
    var nonce = Buffer.alloc(nacl.box.nonceLength, 0);
    randomVectors.forEach(function(vec) {
      var pk1 = dec(vec[0]);
      var sk2 = dec(vec[1]);
      var msg = dec(vec[2]);
      var goodBox = dec(vec[3]);
      var box = nacl.box(msg, nonce, pk1, sk2);
      t.equal(enc(box), enc(goodBox));
      var openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
      t.equal(enc(openedBox), enc(msg));
    });
    t.end();
  });
};
