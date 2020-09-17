(function(nacl) {
'use strict';
  var crypto_secretbox_KEYBYTES = 32,
      crypto_secretbox_NONCEBYTES = 24,
      crypto_secretbox_ZEROBYTES = 32,
      crypto_secretbox_BOXZEROBYTES = 16,
      crypto_scalarmult_BYTES = 32,
      crypto_scalarmult_SCALARBYTES = 32,
      crypto_box_PUBLICKEYBYTES = 32,
      crypto_box_SECRETKEYBYTES = 32,
      crypto_box_BEFORENMBYTES = 32,
      crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
      crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
      crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
      crypto_sign_BYTES = 64,
      crypto_sign_PUBLICKEYBYTES = 32,
      crypto_sign_SECRETKEYBYTES = 64,
      crypto_sign_SEEDBYTES = 32,
      crypto_hash_BYTES = 64;

  nacl.lowlevel = {
    crypto_secretbox_KEYBYTES : crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES : crypto_secretbox_NONCEBYTES,
    crypto_secretbox_ZEROBYTES : crypto_secretbox_ZEROBYTES,
    crypto_secretbox_BOXZEROBYTES : crypto_secretbox_BOXZEROBYTES,
    crypto_scalarmult_BYTES : crypto_scalarmult_BYTES,
    crypto_scalarmult_SCALARBYTES : crypto_scalarmult_SCALARBYTES,
    crypto_box_PUBLICKEYBYTES : crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES : crypto_box_SECRETKEYBYTES,
    crypto_box_BEFORENMBYTES : crypto_box_BEFORENMBYTES,
    crypto_box_NONCEBYTES : crypto_box_NONCEBYTES,
    crypto_box_ZEROBYTES : crypto_box_ZEROBYTES,
    crypto_box_BOXZEROBYTES : crypto_box_BOXZEROBYTES,
    crypto_sign_BYTES : crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES : crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES : crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
    crypto_hash_BYTES : crypto_hash_BYTES
  };

  /* Load tweetnacl-nodeAPI */
  var tweetnacl = require('./tweetnacl_wrapper')();
  var typedef = require('./tweetnacl_typedef.js')();

  /* High-level API */

  function checkLengths(k, n) {
    if (k.length !== crypto_secretbox_KEYBYTES) {
      throw new Error('bad key size');
    }
    if (n.length !== crypto_secretbox_NONCEBYTES) {
      throw new Error('bad nonce size');
    }
  }

  function checkBoxLengths(pk, sk) {
    if (pk.length !== crypto_box_PUBLICKEYBYTES) {
      throw new Error('bad public key size');
    }
    if (sk.length !== crypto_box_SECRETKEYBYTES) {
      throw new Error('bad secret key size');
    }
  }

  function checkBufferTypes() {
    for (let i = 0; i < arguments.length; i++) {
       if (!Buffer.isBuffer(arguments[i])) {
         throw new TypeError('unexpected type, use Buffer');
       }
    }
  }

  function cleanup(arr) {
    for (var i = 0; i < arr.length; i++) {
      arr[i] = 0;
    }
  }

  nacl.util = {};

  nacl.util.encodeBase64 = function(arr) {
    return arr.toString('base64');
  };

  nacl.util.decodeBase64 = function(s) {
    return new Buffer.from(s, 'base64');
  };

  nacl.randomBytes = function(n) {
    var b = Buffer.alloc(n);
    tweetnacl.random_bytes(b, n);
    return b;
  };

  nacl.secretbox = function(msg, nonce, key) {
    checkBufferTypes(msg, nonce, key);
    checkLengths(key, nonce);

    var m = Buffer.alloc(crypto_secretbox_ZEROBYTES + msg.length, 0);
    var c = Buffer.alloc(m.length);

    // Append message into end of the m buffer
    for (var i = 0; i < msg.length; i++) {
      m[i+crypto_secretbox_ZEROBYTES] = msg[i];
    }

    // Encrypt secrect box base on set of nonce, message and key
    tweetnacl.crypto_secretbox(c, m, m.length, nonce, key);
    return c.slice(crypto_secretbox_BOXZEROBYTES);
  };

  nacl.secretbox.open = function(box, nonce, key) {
    checkBufferTypes(box, nonce, key);
    checkLengths(key, nonce);

    var c = Buffer.alloc(crypto_secretbox_BOXZEROBYTES + box.length, 0);
    var m = Buffer.alloc(c.length, 0);
    for (var i = 0; i < box.length; i++) {
      c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
    }
    if (c.length < 32) {
      return false;
    }

    if (tweetnacl.crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) {
      return false;
    }
    return m.slice(crypto_secretbox_ZEROBYTES);
  };

  nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
  nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
  nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

  nacl.scalarMult = function(n, p) {
    checkBufferTypes(n, p);
    if (n.length !== crypto_scalarmult_SCALARBYTES) {
      throw new Error('bad n size');
    }
    if (p.length !== crypto_scalarmult_BYTES) {
      throw new Error('bad p size');
    }
    var q = Buffer.alloc(crypto_scalarmult_BYTES, 0);
    tweetnacl.crypto_scalarmult(q, n, p);
    return q;
  };

  nacl.scalarMult.base = function(n) {
    checkBufferTypes(n);
    if (n.length !== crypto_scalarmult_SCALARBYTES) {
      throw new Error('bad n size');
    }
    var q = Buffer.alloc(crypto_scalarmult_BYTES, 0);
    tweetnacl.crypto_scalarmult_base(q, n);
    return q;
  };

  nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
  nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

  nacl.box = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox(msg, nonce, k);
  };

  nacl.box.before = function(publicKey, secretKey) {
    checkBufferTypes(publicKey, secretKey);
    checkBoxLengths(publicKey, secretKey);
    var k = Buffer.alloc(crypto_box_BEFORENMBYTES, 0);
    tweetnacl.crypto_box_beforenm(k, publicKey, secretKey);
    return k;
  };

  nacl.box.after = nacl.secretbox;

  nacl.box.open = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox.open(msg, nonce, k);
  };

  nacl.box.open.after = nacl.secretbox.open;

  nacl.box.keyPair = function() {
    var pk = Buffer.alloc(crypto_box_PUBLICKEYBYTES, 0);
    var sk = Buffer.alloc(crypto_box_SECRETKEYBYTES, 0);
    tweetnacl.crypto_box_keypair(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.box.keyPair.fromSecretKey = function(secretKey) {
    checkBufferTypes(secretKey);
    if (secretKey.length !== crypto_box_SECRETKEYBYTES) {
      throw new Error('bad secret key size');
    }
    var pk = Buffer.alloc(crypto_box_PUBLICKEYBYTES, 0);
    tweetnacl.crypto_scalarmult_base(pk, secretKey);
    return {publicKey: pk, secretKey: Buffer.from(secretKey)};
  };

  nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
  nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
  nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
  nacl.box.nonceLength = crypto_box_NONCEBYTES;
  nacl.box.overheadLength = nacl.secretbox.overheadLength;

  nacl.sign = function(msg, secretKey) {
    checkBufferTypes(msg, secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES) {
      throw new Error('bad secret key size');
    }
    var signedMsg = Buffer.alloc(crypto_sign_BYTES + msg.length, 0);
    var signedMsgLenght = typedef.ref.alloc(typedef.u64);
    tweetnacl.crypto_sign(signedMsg, signedMsgLenght, msg, msg.length, secretKey);
    return signedMsg;
  };

  nacl.sign.open = function(signedMsg, publicKey) {
    if (arguments.length !== 2){
      throw new Error('nacl.sign.open accepts 2 arguments; did you mean to use nacl.sign.detached.verify?');
    }
    checkBufferTypes(signedMsg, publicKey);
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES){
      throw new Error('bad public key size');
    }
    var tmp = Buffer.alloc(signedMsg.length, 0);
    var tmpLength = typedef.ref.alloc(typedef.u64);
    if (tweetnacl.crypto_sign_open(tmp, tmpLength, signedMsg, signedMsg.length, publicKey) !== 0) {
      return false;
    }
    var m = Buffer.alloc(tmpLength.readUInt8(0), 0);
    for (var i = 0; i < m.length; i++) {
      m[i] = tmp[i];
    }
    return m;
  };

  nacl.sign.detached = function(msg, secretKey) {
    var signedMsg = nacl.sign(msg, secretKey);
    var sig = Buffer.from(signedMsg.slice(0, crypto_sign_BYTES));
    return sig;
  };

  nacl.sign.detached.verify = function(msg, sig, publicKey) {
    checkBufferTypes(msg, sig, publicKey);
    if (sig.length !== crypto_sign_BYTES) {
      throw new Error('bad signature size');
    }
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES) {
      throw new Error('bad public key size');
    }
    var sm = Buffer.alloc(crypto_sign_BYTES + msg.length, 0);
    var m = Buffer.alloc(crypto_sign_BYTES + msg.length, 0);
    var i;
    for (i = 0; i < crypto_sign_BYTES; i++) {
      sm[i] = sig[i];
    }
    for (i = 0; i < msg.length; i++) {
      sm[i+crypto_sign_BYTES] = msg[i];
    }
      var tmpLenght = typedef.ref.alloc(typedef.u64);
    return (tweetnacl.crypto_sign_open(m, tmpLenght, sm, sm.length, publicKey) >= 0);
  };

  nacl.sign.keyPair = function() {
    var pk = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 0);
    var sk = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
    tweetnacl.crypto_sign_keypair_wrap(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.keyPair.fromSecretKey = function(secretKey) {
    checkBufferTypes(secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES) {
      throw new Error('bad secret key size');
    }
    var pk = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 0);
    for (var i = 0; i < pk.length; i++) {
      pk[i] = secretKey[32+i];
    }
    return {publicKey: pk, secretKey: Buffer.from(secretKey)};
  };

  nacl.sign.keyPair.fromSeed = function(seed) {
    checkBufferTypes(seed);
    if (seed.length !== crypto_sign_SEEDBYTES) {
      throw new Error('bad seed size');
    }
    var pk = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 0);
    var sk = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
    for (var i = 0; i < 32; i++) {
      sk[i] = seed[i];
    }
    tweetnacl.crypto_sign_keypair_seeded(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
  nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
  nacl.sign.seedLength = crypto_sign_SEEDBYTES;
  nacl.sign.signatureLength = crypto_sign_BYTES;

  nacl.hash = function(msg) {
    checkBufferTypes(msg);
    var h = Buffer.alloc(crypto_hash_BYTES);
    tweetnacl.crypto_hash(h, msg, msg.length);
    return h;
  };

  nacl.hash.hashLength = crypto_hash_BYTES;

  nacl.verify = function(x, y) {
    checkBufferTypes(x, y);
    // Zero length arguments are considered not equal.
    if (x.length === 0 || y.length === 0) {
      return false;
    }
    if (x.length !== y.length) {
      return false;
    }
    return (tweetnacl.vn(x, 0, y, 0, x.length) === 0) ? true : false;
  };

})(module.exports);
