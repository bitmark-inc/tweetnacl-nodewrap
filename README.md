TweetNaCl-nodewraper.js
============

Port of [TweetNaCl](http://tweetnacl.cr.yp.to) / [NaCl](http://nacl.cr.yp.to/)
to javascript Node.js.

Documentation
=============

* [Overview](#overview)
* [Installation](#installation)
* [Usage](#usage)
  * [Public-key authenticated encryption (box)](#public-key-authenticated-encryption-box)
  * [Secret-key authenticated encryption (secretbox)](#secret-key-authenticated-encryption-secretbox)
  * [Scalar multiplication](#scalar-multiplication)
  * [Signatures](#signatures)
  * [Hashing](#hashing)
  * [Random bytes generation](#random-bytes-generation)
  * [Constant-time comparison](#constant-time-comparison)
  * [Utilities](#utilities)
* [Examples](#examples)
* [System requirements](#system-requirements)
* [Development and testing](#development-and-testing)
* [Contributors](#contributors)
* [Who uses it](#who-uses-it)


Overview
--------

The primary goal of this project is to compile and wrap all of function of TweetNaCl to into the Node.js library with node-ffi and node-ref.Plus
a thin layer of idiomatic high-level API on top of it.

There are two main classes, you can use both of it:

* `tweetnacl_wrapper.js` is wraper class of TweetNaCl.
* `nacl.js` the original + high-level API.


System requirements
-------------------

Tweetnacl-nodewrap.js supports for all of devices:

Other systems:

* [Node.js](https://nodejs.org/en/) (we test on 0.10 and later)
* g++: Install g++ to compile C++ code
* [node-gyp](https://github.com/nodejs/node-gyp): native addon build tool

Installation
------------

You can install tweetnacl_wrapper.is via a package manager:

[NPM](https://www.npmjs.org/):

    $ npm install tweetnacl-nodewrap

or [download source code](https://github.com/bitmark-inc/tweetnacl-nodewrap).

* NOTE: When you want to use with node-webkit version, please follow these steps bellow

	* Install [nw-gyp](https://github.com/nwjs/nw.js): native addon build tool for node-webkit.
	* Rebuild `node-ref` with `nw-gyp`

		```
		$ cd node_modules/ref
		$ nw-gyp rebuild --target=xxx (xxx: your nw-gyp version)
		
		```
	* Rebuild `tweetnacl-nodewrap` with `nw-gyp`
	
		```
		$ cd <root folder of tweetnacl-nodewrap>
		$ nw-gyp rebuild --target=xxx (xxx: your nw-gyp version)
		```


Usage
------

All API functions accept and return Buffer as `base64`.  You can easy to decode by `nacl.util.encodeBase64(value)` or `toString('base64')`.

### Public-key authenticated encryption (box)

Implements *curve25519-xsalsa20-poly1305*.

#### nacl.box.keyPair()

Generates a new random key pair for box and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // Buffer with 32-byte public key
       secretKey: ...   // Buffer with 32-byte secret key
    }


#### nacl.box.keyPair.fromSecretKey(secretKey)

Returns a key pair for box with public key corresponding to the given secret
key.

#### nacl.box(message, nonce, theirPublicKey, mySecretKey)

Encrypt and authenticates message using peer's public key, our secret key, and
the given nonce, which must be unique for each distinct message for a key pair.

Returns an encrypted and authenticated message, which is
`nacl.box.overheadLength` longer than the original message.

#### nacl.box.open(box, nonce, theirPublicKey, mySecretKey)

Authenticates and decrypts the given box with peer's public key, our secret
key, and the given nonce.

Returns the original message, or `false` if authentication fails.

#### nacl.box.before(theirPublicKey, mySecretKey)

Returns a precomputed shared key which can be used in `nacl.box.after` and
`nacl.box.open.after`.

#### nacl.box.after(message, nonce, sharedKey)

Same as `nacl.box`, but uses a shared key precomputed with `nacl.box.before`.

#### nacl.box.open.after(box, nonce, sharedKey)

Same as `nacl.box.open`, but uses a shared key precomputed with `nacl.box.before`.

#### nacl.box.publicKeyLength = 32

Length of public key in bytes.

#### nacl.box.secretKeyLength = 32

Length of secret key in bytes.

#### nacl.box.sharedKeyLength = 32

Length of precomputed shared key in bytes.

#### nacl.box.nonceLength = 24

Length of nonce in bytes.

#### nacl.box.overheadLength = 16

Length of overhead added to box compared to original message.


### Secret-key authenticated encryption (secretbox)

Implements *xsalsa20-poly1305*.

#### nacl.secretbox(message, nonce, key)

Encrypt and authenticates message using the key and the nonce. The nonce must
be unique for each distinct message for this key.

Returns an encrypted and authenticated message, which is
`nacl.secretbox.overheadLength` longer than the original message.

#### nacl.secretbox.open(box, nonce, key)

Authenticates and decrypts the given secret box using the key and the nonce.

Returns the original message, or `false` if authentication fails.

#### nacl.secretbox.keyLength = 32

Length of key in bytes.

#### nacl.secretbox.nonceLength = 24

Length of nonce in bytes.

#### nacl.secretbox.overheadLength = 16

Length of overhead added to secret box compared to original message.


### Scalar multiplication

Implements [e25519](http://ed25519.cr.yp.to).

#### nacl.scalarMult(n, p)

Multiplies an integer `n` by a group element `p` and returns the resulting
group element.

#### nacl.scalarMult.base(n)

Multiplies an integer `n` by a standard group element and returns the resulting
group element.

#### nacl.scalarMult.scalarLength = 32

Length of scalar in bytes.

#### nacl.scalarMult.groupElementLength = 32

Length of group element in bytes.


### Signatures

Implements [ed25519](http://ed25519.cr.yp.to).

#### nacl.sign.keyPair()

Generates new random key pair for signing and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // Buffer with 32-byte public key
       secretKey: ...   // Buffer with 64-byte secret key
    }

#### nacl.sign.keyPair.fromSecretKey(secretKey)

Returns a signing key pair with public key corresponding to the given
64-byte secret key. The secret key must have been generated by
`nacl.sign.keyPair` or `nacl.sign.keyPair.fromSeed`.

#### nacl.sign.keyPair.fromSeed(seed)

Returns a new signing key pair generated deterministically from a 32-byte seed.
The seed must contain enough entropy to be secure. This method is not
recommended for general use: instead, use `nacl.sign.keyPair` to generate a new
key pair from a random seed.

#### nacl.sign(message, secretKey)

Signs the message using the secret key and returns a signed message.

#### nacl.sign.open(signedMessage, publicKey)

Verifies the signed message and returns the message without signature.

Returns `null` if verification failed.

#### nacl.sign.detached(message, secretKey)

Signs the message using the secret key and returns a signature.

#### nacl.sign.detached.verify(message, signature, publicKey)

Verifies the signature for the message and returns `true` if verification
succeeded or `false` if it failed.

#### nacl.sign.publicKeyLength = 32

Length of signing public key in bytes.

#### nacl.sign.secretKeyLength = 64

Length of signing secret key in bytes.

#### nacl.sign.seedLength = 32

Length of seed for `nacl.sign.keyPair.fromSeed` in bytes.

#### nacl.sign.signatureLength = 64

Length of signature in bytes.


### Hashing

Implements *SHA-512*.

#### nacl.hash(message)

Returns SHA-512 hash of the message.

#### nacl.hash.hashLength = 64

Length of hash in bytes.


### Random bytes generation

#### nacl.randomBytes(length)
Implements *RAND_bytes openSSL*.

Returns a Buffer of `base64` of the given length containing random bytes of
cryptographic quality.

**Implementation note**

Tweetnacl-nodewrap.js uses the RAND_bytes methods of [openSSL](https://www.openssl.org/docs/manmaster/crypto/RAND_bytes.html). 

### Constant-time comparison

#### nacl.verify(x, y)

Compares `x` and `y` in constant time and returns `true` if their lengths are
non-zero and equal, and their contents are equal.

Returns `false` if either of the arguments has zero length, or arguments have
different lengths, or their contents differ.

### Thanks

Special thanks to @TooTallNate who is owner of node-ffi and node-ref, and also help us quickly resolve some issues.


# License

Copyright (c) 2014-2015 Bitmark Inc (support@bitmark.com).

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.