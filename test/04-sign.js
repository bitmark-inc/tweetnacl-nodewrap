var nacl = require('../' + (process.env.NACL_SRC || 'nacl.js'));
var test = require('tape');

var specVectors = require('./data/sign.spec');

var enc = nacl.util.encodeBase64,
    dec = nacl.util.decodeBase64;

test('nacl.sign.keyPair', function(t) {
  var keys = nacl.sign.keyPair();
  t.ok(keys.secretKey && keys.secretKey.length === nacl.sign.secretKeyLength, 'has secret key');
  t.ok(keys.publicKey && keys.publicKey.length === nacl.sign.publicKeyLength, 'has public key');
  t.notEqual(enc(keys.secretKey), enc(keys.publicKey));
  var newKeys = nacl.sign.keyPair();
  t.notEqual(enc(newKeys.secretKey), enc(keys.secretKey), 'two keys differ');
  t.end();
});

test('nacl.sign.keyPair.fromSecretKey', function(t) {
  var k1 = nacl.sign.keyPair();
  var k2 = nacl.sign.keyPair.fromSecretKey(k1.secretKey);
  t.equal(enc(k2.secretKey), enc(k1.secretKey));
  t.equal(enc(k2.publicKey), enc(k1.publicKey));
  t.end();
});

test('nacl.sign and nacl.sign.open specified vectors', function(t) {
  var keys = nacl.sign.keyPair();
  var m = new Buffer(100);
  for (var i = 0; i < m.length; i++) m[i] = i & 0xff;

  var signedMsg = nacl.sign(m, keys.secretKey);
  t.ok(signedMsg, 'Message must be signed');
  var openedMsg = nacl.sign.open(signedMsg, keys.publicKey);
  t.ok(openedMsg, 'Signed Message must be opened');
  t.end();
});
