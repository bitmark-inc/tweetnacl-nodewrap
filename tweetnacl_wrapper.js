// gcc -shared -fpic tweetnacl.c -o libtweetnacl.so
// gcc -shared -fpic randombytes.c -o librandombytes.so

var ffi = require('./lib/ffi');
var ref = require('ref');
var ArrayType = require('ref-array');

// typedef
var sv = ref.types.void;
var u8 = ref.types.CString;
var u8Ptr = ref.refType(u8);
var u32 = ref.types.ulong;
var u32Ptr = ref.refType(u32);
var u64 = ref.types.ulonglong;
var u64Ptr = ref.refType(u64);
var i64 = ref.types.longlong;
var i64Ptr = ref.refType(i64);
var i64Array = ArrayType(i64);
var i64ArrayPtr = ref.refType(i64Array);
var gf = ArrayType(i64);
var gfPtr = ref.refType(gf);
var gfArray = ArrayType(gf);
var gfArrayPtr = ref.refType(gfArray);

module.exports = function() {
  var libencrypt = ffi.Library('./libtweetnacl', {
    'random_bytes': [sv, [u8Ptr, 'int']],
    'st32': [sv, [u8Ptr, u32Ptr]],
    'ts64': [sv, [u8Ptr, u64Ptr]],
    'crypto_verify_16': ['int', [u8, u8]],
    'crypto_verify_32': ['int', [u8, u8]],
    'core': [sv, [u8Ptr, u8, u8, u8, 'int']],
    'crypto_core_salsa20': ['int', [u8Ptr, u8, u8, u8]],
    'crypto_core_hsalsa20': ['int', [u8Ptr, u8, u8, u8]],
    'crypto_stream_salsa20_xor': ['int', [u8Ptr, u8, u64Ptr, u8, u8]],
    'crypto_stream_salsa20': ['int', [u8Ptr, u64Ptr, u8, u8]],
    'crypto_stream': ['int', [u8Ptr, u64Ptr, u8, u8]],
    'crypto_stream_xor': ['int', [u8Ptr, u8, u64Ptr, u8, u8]],
    'add1305': [sv, [u32Ptr, u32]],
    'crypto_onetimeauth': ['int', [u8Ptr, u8, u64Ptr, u8]],
    'crypto_onetimeauth_verify': ['int', [u8, u8, u64Ptr, u8]],
    'crypto_secretbox': ['int', [u8Ptr, u8Ptr, u64, u8Ptr, u8Ptr]],
    'crypto_secretbox_open': ['int', [u8Ptr, u8Ptr, u64, u8Ptr, u8Ptr]],
    'set25519': [sv, [gfPtr, gf]],
    'car25519': [sv, [gfPtr]],
    'sel25519': [sv, [gfPtr, gfPtr, 'int']],
    'pack25519': [sv, [u8Ptr, gf]],
    // 'neq25519': [sv, [gf, gf]],
    // 'par25519': [sv, [gf]],
    'unpack25519': [sv, [gfPtr, u8]],
    'A': [sv, [gfPtr, gf, gf]],
    'Z': [sv, [gfPtr, gf, gf]],
    'M': [sv, [gfPtr, gf, gf]],
    'S': [sv, [gfPtr, gf, gf]],
    'inv25519': [sv, [gfPtr, gf]],
    'pow2523': [sv, [gfPtr, gf]],
    'crypto_scalarmult': ['int', [u8Ptr, u8, u8]],
    'crypto_scalarmult_base': ['int', [u8Ptr, u8]],
    'crypto_box_keypair': ['int', [u8Ptr, u8Ptr]],
    'crypto_box_beforenm': ['int', [u8Ptr, u8, u8]],
    'crypto_box_afternm':  ['int', [u8Ptr, u8, u64Ptr, u8, u8]],
    'crypto_box_open_afternm': ['int', [u8Ptr, u8, u64Ptr, u8, u8]],
    'crypto_box': ['int', [u8Ptr, u8, u64Ptr, u8, u8, u8]],
    'crypto_box_open': ['int', [u8Ptr, u8, u64Ptr, u8, u8, u8]],
    'crypto_hashblocks': ['int', [u8Ptr, u8, u64Ptr]],
    'crypto_hash': ['int', [u8Ptr, u8, u64Ptr]],
    'add': [sv, [gfArrayPtr, gfArrayPtr]],
    'cswap': [sv, [gfArrayPtr, gfArrayPtr, u8Ptr]],
    'pack': [sv, [u8Ptr, gfArrayPtr]],
    'scalarmult': [sv, [gfArrayPtr, gfArrayPtr, u8]],
    'scalarbase': [sv, [gfArrayPtr, u8]],
    'crypto_sign_keypair': ['int', [u8Ptr, u8Ptr]],
    'modL': [sv, [u8Ptr, i64ArrayPtr]],
    'reduce': [sv, [u8Ptr]],
    'crypto_sign': ['int', [u8Ptr, u64Ptr, u8, u64Ptr, u8]],
    // 'unpackneg': ['int', [gfArrayPtr, u8]],
    'crypto_sign_open': ['int', [u8Ptr, u64Ptr, u8, u64Ptr, u8]]
  })

  return libencrypt;
}()