var nacl = require('../' + (process.env.NACL_SRC || 'nacl.js'));
var test = require('tape');

var randomVectors = require('./data/secretbox.random');

var enc = nacl.util.encodeBase64,
    dec = nacl.util.decodeBase64;

module.exports = function() {
  test('nacl.secretbox random test vectors', function(t) {
    randomVectors.forEach(function(vec) {
      var key = dec(vec[0]);
      var nonce = dec(vec[1]);
      var msg = dec(vec[2]);
      var goodBox = dec(vec[3]);
      var box = nacl.secretbox(msg, nonce, key);
      t.ok(box, 'box should be created');
      t.equal(enc(box), enc(goodBox));
      var openedBox = nacl.secretbox.open(goodBox, nonce, key);
      t.ok(openedBox, 'box should open');
      t.equal(enc(openedBox), enc(msg));
    });
    t.end();
  });
}