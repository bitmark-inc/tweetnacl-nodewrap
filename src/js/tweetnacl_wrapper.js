// gcc -shared -fpic tweetnacl.c -o libtweetnacl.so
// gcc -dynamiclib -undefined suppress -flat_namespace tweetnacl.c -o libtweetnacl.dylib
// gcc -shared -fpic randombytes.c -o librandombytes.so

var ffi = require('ffi');
var typedef = require('./tweetnacl_typedef.js')();
var path = require('path');
var crypto = require('crypto');
var libPath = '';
if (ffi.LIB_EXT === '.dll') {
  libPath = path.resolve(__dirname.replace('\\js', '\\'), 'c\\libtweetnacl');
} else {
  libPath = path.resolve(__dirname.replace('/js', '/'), 'c/libtweetnacl');
}

module.exports = function() {
  var libencrypt = ffi.Library(libPath, {
    'st32': [typedef.sv, [typedef.u8Ptr, typedef.u32]],
    'ts64': [typedef.sv, [typedef.u8Ptr, typedef.u64]],
    'crypto_verify_16': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_verify_32': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'core': [typedef.sv, [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr, 'int']],
    'crypto_core_salsa20': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_core_hsalsa20': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_stream_salsa20_xor': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_stream_salsa20': ['int', [typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_stream': ['int', [typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_stream_xor': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'add1305': [typedef.sv, [typedef.u32, typedef.u32]],
    'crypto_onetimeauth': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]],
    'crypto_onetimeauth_verify': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]],
    'crypto_secretbox': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_secretbox_open': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_scalarmult': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_scalarmult_base': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    // 'crypto_box_keypair': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_beforenm': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_afternm':  ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_open_afternm': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_open': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_hashblocks': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64]],
    'crypto_hash': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64]],
    'crypto_sign_keypair': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'reduce': [typedef.sv, [typedef.u8Ptr]],
    'crypto_sign': ['int', [typedef.u8Ptr, typedef.u64Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]],
    'crypto_sign_open': ['int', [typedef.u8Ptr, typedef.u64Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]]
  });

  libencrypt['crypto_box_keypair'] = function(pk, sk) {
    crypto.randomBytes(32).copy(sk);
    return libencrypt.crypto_scalarmult_base(pk, sk);
  };

  libencrypt['crypto_sign_keypair_wrap'] = function(pk, sk) {
    crypto.randomBytes(32).copy(sk);
    return libencrypt.crypto_sign_keypair(pk, sk);
  };

  libencrypt['crypto_sign_keypair_seeded'] = function(pk, sk) {
    return libencrypt.crypto_sign_keypair(pk, sk);
  };

  libencrypt['random_bytes'] = function(b, n) {
    crypto.randomBytes(n).copy(b);
  };

  return libencrypt;
};