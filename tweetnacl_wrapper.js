// gcc -shared -fpic tweetnacl.c -o libtweetnacl.so
// gcc -shared -fpic randombytes.c -o librandombytes.so

var ffi = require('./lib/ffi');
var typedef = require('./tweetnacl_typedef.js')

module.exports = function() {
  var libencrypt = ffi.Library('./libtweetnacl', {
    'random_bytes': [typedef.sv, [typedef.u8Ptr, 'int']],
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
    'crypto_box_keypair': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_beforenm': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_afternm':  ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_open_afternm': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_box_open': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr, typedef.u8Ptr, typedef.u8Ptr]],
    'crypto_hashblocks': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64]],
    'crypto_hash': ['int', [typedef.u8Ptr, typedef.u8Ptr, typedef.u64]],
    'crypto_sign_keypair': ['int', [typedef.u8Ptr, typedef.u8Ptr]],
    'modL': [typedef.sv, [typedef.u8Ptr, typedef.i64ArrayPtr]],
    'reduce': [typedef.sv, [typedef.u8Ptr]],
    'crypto_sign': ['int', [typedef.u8Ptr, typedef.u64Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]],
    'crypto_sign_open': ['int', [typedef.u8Ptr, typedef.u64Ptr, typedef.u8Ptr, typedef.u64, typedef.u8Ptr]]
    // 'set25519': [typedef.sv, [gfPtr, gf]],
    // 'car25519': [typedef.sv, [gfPtr]],
    // 'sel25519': [typedef.sv, [gfPtr, gfPtr, 'int']],
    // 'pack25519': [typedef.sv, [typedef.u8Ptr, gf]],
    // 'neq25519': [typedef.sv, [gf, gf]],
    // 'par25519': [typedef.sv, [gf]],
    // 'unpack25519': [typedef.sv, [gfPtr, u8]],
    // 'unpackneg': ['int', [gfArrayPtr, u8]],
    // 'A': [typedef.sv, [gfPtr, gf, gf]],
    // 'Z': [typedef.sv, [gfPtr, gf, gf]],
    // 'M': [typedef.sv, [gfPtr, gf, gf]],
    // 'S': [typedef.sv, [gfPtr, gf, gf]],
    // 'inv25519': [typedef.sv, [gfPtr, gf]],
    // 'pow2523': [typedef.sv, [gfPtr, gf]],
    // 'add': [typedef.sv, [gfArrayPtr, gfArrayPtr]],
    // 'cswap': [typedef.sv, [gfArrayPtr, gfArrayPtr, typedef.u8Ptr]],
    // 'pack': [typedef.sv, [typedef.u8Ptr, gfArrayPtr]],
    // 'scalarmult': [typedef.sv, [gfArrayPtr, gfArrayPtr, u8]],
    // 'scalarbase': [typedef.sv, [gfArrayPtr, u8]],
  })

  return libencrypt;
}()