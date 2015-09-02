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
    crypto_core_hsalsa20: crypto_core_hsalsa20,
    crypto_stream_xor : crypto_stream_xor,
    crypto_stream : crypto_stream,
    crypto_stream_salsa20_xor : crypto_stream_salsa20_xor,
    crypto_stream_salsa20 : crypto_stream_salsa20,
    crypto_onetimeauth : crypto_onetimeauth,
    crypto_onetimeauth_verify : crypto_onetimeauth_verify,
    crypto_verify_16 : crypto_verify_16,
    crypto_verify_32 : crypto_verify_32,
    crypto_secretbox : crypto_secretbox,
    crypto_secretbox_open : crypto_secretbox_open,
    crypto_scalarmult : crypto_scalarmult,
    crypto_scalarmult_base : crypto_scalarmult_base,
    crypto_box_beforenm : crypto_box_beforenm,
    crypto_box_afternm : crypto_box_afternm,
    crypto_box : crypto_box,
    crypto_box_open : crypto_box_open,
    crypto_box_keypair : crypto_box_keypair,
    crypto_hash : crypto_hash,
    crypto_sign : crypto_sign,
    crypto_sign_keypair : crypto_sign_keypair,
    crypto_sign_open : crypto_sign_open,

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

  /* High-level API */

  function checkLengths(k, n) {
    if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
    if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error('bad nonce size');
  }

  function checkBoxLengths(pk, sk) {
    if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error('bad public key size');
    if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error('bad secret key size');
  }

  function checkArrayTypes() {
    var t, i;
    for (i = 0; i < arguments.length; i++) {
       if ((t = Object.prototype.toString.call(arguments[i])) !== '[object Uint8Array]')
         throw new TypeError('unexpected type ' + t + ', use Uint8Array');
    }
  }

  function cleanup(arr) {
    for (var i = 0; i < arr.length; i++) arr[i] = 0;
  }

  nacl.util = {};

  nacl.util.encodeBase64 = function(arr) {
    if (typeof btoa === 'undefined') {
      return (new Buffer(arr)).toString('base64');
    } else {
      var i, s = [], len = arr.length;
      for (i = 0; i < len; i++) s.push(String.fromCharCode(arr[i]));
      return btoa(s.join(''));
    }
  };

  nacl.util.decodeBase64 = function(s) {
    if (typeof atob === 'undefined') {
      return new Uint8Array(Array.prototype.slice.call(new Buffer(s, 'base64'), 0));
    } else {
      var i, d = atob(s), b = new Uint8Array(d.length);
      for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
      return b;
    }
  };

  nacl.randomBytes = function(n) {
    var b = new Uint8Array(n);
    randombytes(b, n);
    return b;
  };

  nacl.secretbox = function(msg, nonce, key) {
    checkArrayTypes(msg, nonce, key);
    checkLengths(key, nonce);
    var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
    var c = new Uint8Array(m.length);
    for (var i = 0; i < msg.length; i++) m[i+crypto_secretbox_ZEROBYTES] = msg[i];
    crypto_secretbox(c, m, m.length, nonce, key);
    return c.subarray(crypto_secretbox_BOXZEROBYTES);
  };

  nacl.secretbox.open = function(box, nonce, key) {
    checkArrayTypes(box, nonce, key);
    checkLengths(key, nonce);
    var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
    var m = new Uint8Array(c.length);
    for (var i = 0; i < box.length; i++) c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
    if (c.length < 32) return false;
    if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return false;
    return m.subarray(crypto_secretbox_ZEROBYTES);
  };

  nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
  nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
  nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

  nacl.scalarMult = function(n, p) {
    checkArrayTypes(n, p);
    if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
    if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult(q, n, p);
    return q;
  };

  nacl.scalarMult.base = function(n) {
    checkArrayTypes(n);
    if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
    var q = new Uint8Array(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(q, n);
    return q;
  };

  nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
  nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

  nacl.box = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox(msg, nonce, k);
  };

  nacl.box.before = function(publicKey, secretKey) {
    checkArrayTypes(publicKey, secretKey);
    checkBoxLengths(publicKey, secretKey);
    var k = new Uint8Array(crypto_box_BEFORENMBYTES);
    crypto_box_beforenm(k, publicKey, secretKey);
    return k;
  };

  nacl.box.after = nacl.secretbox;

  nacl.box.open = function(msg, nonce, publicKey, secretKey) {
    var k = nacl.box.before(publicKey, secretKey);
    return nacl.secretbox.open(msg, nonce, k);
  };

  nacl.box.open.after = nacl.secretbox.open;

  nacl.box.keyPair = function() {
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.box.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_box_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
    crypto_scalarmult_base(pk, secretKey);
    return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
  };

  nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
  nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
  nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
  nacl.box.nonceLength = crypto_box_NONCEBYTES;
  nacl.box.overheadLength = nacl.secretbox.overheadLength;

  nacl.sign = function(msg, secretKey) {
    checkArrayTypes(msg, secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var signedMsg = new Uint8Array(crypto_sign_BYTES+msg.length);
    crypto_sign(signedMsg, msg, msg.length, secretKey);
    return signedMsg;
  };

  nacl.sign.open = function(signedMsg, publicKey) {
    if (arguments.length !== 2)
      throw new Error('nacl.sign.open accepts 2 arguments; did you mean to use nacl.sign.detached.verify?');
    checkArrayTypes(signedMsg, publicKey);
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
      throw new Error('bad public key size');
    var tmp = new Uint8Array(signedMsg.length);
    var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
    if (mlen < 0) return null;
    var m = new Uint8Array(mlen);
    for (var i = 0; i < m.length; i++) m[i] = tmp[i];
    return m;
  };

  nacl.sign.detached = function(msg, secretKey) {
    var signedMsg = nacl.sign(msg, secretKey);
    var sig = new Uint8Array(crypto_sign_BYTES);
    for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
    return sig;
  };

  nacl.sign.detached.verify = function(msg, sig, publicKey) {
    checkArrayTypes(msg, sig, publicKey);
    if (sig.length !== crypto_sign_BYTES)
      throw new Error('bad signature size');
    if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
      throw new Error('bad public key size');
    var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
    var m = new Uint8Array(crypto_sign_BYTES + msg.length);
    var i;
    for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
    for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
    return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0);
  };

  nacl.sign.keyPair = function() {
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk, sk);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.keyPair.fromSecretKey = function(secretKey) {
    checkArrayTypes(secretKey);
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
      throw new Error('bad secret key size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32+i];
    return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
  };

  nacl.sign.keyPair.fromSeed = function(seed) {
    checkArrayTypes(seed);
    if (seed.length !== crypto_sign_SEEDBYTES)
      throw new Error('bad seed size');
    var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
    var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
    for (var i = 0; i < 32; i++) sk[i] = seed[i];
    crypto_sign_keypair(pk, sk, true);
    return {publicKey: pk, secretKey: sk};
  };

  nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
  nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
  nacl.sign.seedLength = crypto_sign_SEEDBYTES;
  nacl.sign.signatureLength = crypto_sign_BYTES;

  nacl.hash = function(msg) {
    checkArrayTypes(msg);
    var h = new Uint8Array(crypto_hash_BYTES);
    crypto_hash(h, msg, msg.length);
    return h;
  };

  nacl.hash.hashLength = crypto_hash_BYTES;

  nacl.verify = function(x, y) {
    checkArrayTypes(x, y);
    // Zero length arguments are considered not equal.
    if (x.length === 0 || y.length === 0) return false;
    if (x.length !== y.length) return false;
    return (vn(x, 0, y, 0, x.length) === 0) ? true : false;
  };

  nacl.setPRNG = function(fn) {
    randombytes = fn;
  };

  (function() {
    // Initialize PRNG if environment provides CSPRNG.
    // If not, methods calling randombytes will throw.
    var crypto;
    if (typeof window !== 'undefined') {
      // Browser.
      if (window.crypto && window.crypto.getRandomValues) {
        crypto = window.crypto; // Standard
      } else if (window.msCrypto && window.msCrypto.getRandomValues) {
        crypto = window.msCrypto; // Internet Explorer 11+
      }
      if (crypto) {
        nacl.setPRNG(function(x, n) {
          var i, v = new Uint8Array(n);
          crypto.getRandomValues(v);
          for (i = 0; i < n; i++) x[i] = v[i];
          cleanup(v);
        });
      }
    } else if (typeof require !== 'undefined') {
      // Node.js.
      crypto = require('crypto');
      if (crypto) {
        nacl.setPRNG(function(x, n) {
          var i, v = crypto.randomBytes(n);
          for (i = 0; i < n; i++) x[i] = v[i];
          cleanup(v);
        });
      }
    }
  })();

})(typeof module !== 'undefined' && module.exports ? module.exports : (window.nacl = window.nacl || {}));
