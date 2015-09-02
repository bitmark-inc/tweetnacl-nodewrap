/* Test calss for convert library */

var ref = require('ref');
var assert = require('assert');
var ArrayType = require('ref-array');
var convertedLibary = require('./tweetnacl_wrapper');

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

var u8PtrOut1 = new Buffer(32);
var u8PtrOut2 = new Buffer(32);
var mySecretKey = 'V0Gc/QaeSvHTqxMBFBW/d8E8hsg8YXH6Qj4JmzWWkzI=';
var myPublicKey = 'lAOS8PCuvK51JOGMh7a8/ngj8yTSkp2sVlJ8ZY/pABY=';
var theirPublcKey = 'axvuknosFJ27gTRSUoGa8KgACO4AqX3Hqowlz1BWKzU=';
var theirPublicKey = 'C7MEFFyVmQ+7CnbCmNFr271gcdGYgWSp8U9RhS1a1Rg=';
var boxbefore = 'VnvLtuvs+gwM50zmAJhRdoF+kx6P0C+eD8gEoe8WTHc=';
// var boxAfter =  '2c205b75385074722c2075382c2075382c2075385d5d2c0a2020202027637279';
var secretBox = 'AAAAAAAAAAAAAAAAAAAAAA2JhvPBmp8Hx25KwGo7j1g=';
var nonce =     'nonce to encrypt                ';
var msg =       'message to encrypt              ';
var scalarmul_1 = 'qTt5ihiQhxxOZ+KJyTmks9+GVsA4OfZScMDKVL9tz3U=';
var scalarmul_2 = 'Tb3on013uC30mOpt8q0DSH3TZdCEyYx9VcKM09Djt1w=';


// --START--- crypto_box_keypair: Test Box create keypair function --------------------------------

var test = convertedLibary.crypto_box_keypair(u8PtrOut1, u8PtrOut2);
console.log('Test crypto_box_keypair: ' + test + ' -- ' + u8PtrOut1.toString('base64') + ' -- ' + u8PtrOut2.toString('base64'));
assert.equal(test, 0);

// --END--- crypto_box_keypair: Test Box create keypair function --------------------------------

// --START--- crypto_box_beforenm: Test Box create keypair function --------------------------------
u8PtrOut1 = new Buffer(32);

var test = convertedLibary.crypto_box_beforenm(u8PtrOut1, theirPublicKey, mySecretKey);
console.log('Test crypto_box_beforenm: ' + test + ' -- ' + u8PtrOut1.toString('base64'));
assert.equal(test, 0);

// --END--- crypto_box_beforenm: Test Box create keypair function --------------------------------

// --START--- crypto_secretbox: Test Box create keypair function --------------------------------
u8PtrOut1 = new Buffer(32);

var test = convertedLibary.crypto_secretbox(u8PtrOut1, msg, msg.length, nonce, boxbefore);
console.log('Test crypto_secretbox: ' + test + ' -- ' + u8PtrOut1.toString('base64'));
assert.equal(test, 0);

// --END--- crypto_secretbox: Test Box create keypair function --------------------------------

// --START--- crypto_secretbox_open: Test Box create keypair function --------------------------------
// u8PtrOut1 = new Buffer(32);

// var test = convertedLibary.crypto_secretbox_open(u8PtrOut1, secretBox, secretBox.length, nonce, boxbefore);
// console.log('Test crypto_secretbox_open: ' + test + ' -- ' + u8PtrOut1.toString('base64'));
// assert.equal(test, 0);

// --END--- crypto_secretbox_open: Test Box create keypair function --------------------------------

// --START--- crypto_secretbox_open: Test Box create keypair function --------------------------------
u8PtrOut1 = new Buffer(32);

var test = convertedLibary.crypto_scalarmult(u8PtrOut1, scalarmul_1, scalarmul_2);
console.log('Test crypto_scalarmult: ' + test + ' -- ' + u8PtrOut1.toString('base64'));
assert.equal(test, 0);

// --END--- crypto_scalarmult: Test Box create keypair function --------------------------------


// --START--- crypto_scalarmult_base: Test Box create keypair function --------------------------------
u8PtrOut1 = new Buffer(32);

var test = convertedLibary.crypto_scalarmult_base(u8PtrOut1, mySecretKey);
console.log('Test crypto_scalarmult_base: ' + test + ' -- ' + u8PtrOut1.toString('base64'));
assert.equal(test, 0);

// --END--- crypto_scalarmult_base: Test Box create keypair function --------------------------------

