var nacl = require('../' + (process.env.NACL_SRC || 'nacl.js'));
/* Load tweetnacl-nodeAPI */
var tweetnacl = require('../tweetnacl_wrapper');
var test = require('tape');

var enc = nacl.util.encodeBase64,
    dec = nacl.util.decodeBase64;

test('nacl.secretbox random', function(t) {

  for (var i = 0; i < 1; i ++) {
    var key = new Buffer(32);
    var sk = new Buffer(32);
    var pk = new Buffer(32);
    var nonce = new Buffer(24);
    var msg = new Buffer('Message to encript', 'base64');

    // random byte for nonce
    // tweetnacl.random_bytes(msg, 32)
    for (i = 0; i < nonce.length; i++) nonce[i] = (32+i) & 0xff;

    console.log('Nonce : ' + nonce.length);
    console.log('msg : ' + enc(msg));

    // Generate pubickey and private key
    var val = tweetnacl.crypto_box_keypair(pk, sk);
    t.equal(val, 0);
    console.log('sk_1 : ' + enc(sk));

    // create secret Box
    var box = nacl.secretbox(msg, nonce, sk);
    t.ok(box, 'box should be created');
    console.log('Secret box :  ' + enc(box));
    console.log('sk_2 : ' + enc(sk));

    var openedBox = nacl.secretbox.open(box, nonce, sk);
    t.ok(openedBox, 'box should open');
    t.equal(enc(openedBox), enc(msg));
    console.log('openedBox : ' + enc(openedBox));
  }
  t.end();
});

