This is `cretrit` (pronounced "cre-TRIT"), a Rust library for performing comparison-revealing cryptographic operations (encryption, comparison) on arbitrary data.
It implements the two-value and three-value encrypted comparison algorithms described in the paper [Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds](https://eprint.iacr.org/2016/612.pdf) by Kevin Lewi and David J. Wu, of Stanford University.

What this library allows you to do is to take plaintext values, encrypt them, and then perform comparison operations on the encrypted forms that produce results identical to the equivalent comparison operations on the plaintexts.
This is typically useful for performing ordering (where the comparison is "is this value less-than, equal-to, or greater-than that value?") and equality ("is this value equal-to or not-equal-to that value?").
However the library is designed to accommodate other comparison operators, in case the need arises.
To provide implementation examples, and satisfy common use cases, generic ordering and equality ciphertext types are also provided.

If the ideas in this library intrigue you, but the idea of fiddling around with these low-level primitives sounds a bit tedious, you may wish to check out the rest of [the Enquo Project](https://enquo.org).
The Enquo Project exists to provide encrypted, queryable datastores for everyone, which uses comparison-revealing cryptography extensively.


# Security Status

This library has NOT been audited by any competent third party for implementation flaws.
If you would like to undertake, or sponsor, such an audit, please get in touch.

If you believe you have found a security flaw in this library, an e-mail to `security@enquo.org` would be appreciated.





# Usage

To use the existing ordering and equality types, you just have to select a *cipher suite*, and then `use` the module in that cipher suite that corresponds to the operation you wish to perform.
At present, only one cipher suite is available, named `aes128v1`, and there are `ore` (order-revealing encryption) and `ere` (equality-revealing encryption) modules.
From there, you instantiate a `Cipher` whose generic parameters represent the number of blocks (`N`) and the "width" of each block (the number of values representable by each block, `W`), giving it a key to use for encryption.
For example:

```rust
// Let's do some order-revealing encryption!
use cretrit::aes128v1::ore;

// This cipher has four blocks, the value of each is in the range
// 0-255.  Hence, this cipher can represent the ordering of values
// between 0 and 256^4-1 (aka 2**32-1), which corresponds to a 32-bit
// unsigned integer.
// The `[0; u16]` is the key; for real-world usage, use a cryptographically-secure key, please!
let cipher = ore::Cipher::<4, 256>::new([0u8; 16]).unwrap();
```

This cipher is how you encrypt plaintexts.
Internally, plaintexts are an array of the value of each block, and you can use that representation if you like.
For encrypting unsigned integers, there are implementations of the `From` trait that allow you to pass the integers in directly, like this:

```rust
# use cretrit::aes128v1::ore;
# let cipher = ore::Cipher::<4, 256>::new([0u8; 16]).unwrap();

let forty_two: u32 = 42;
let ore_forty_two = cipher.full_encrypt(forty_two.into()).unwrap();
let over_nine_thousand: u32 = 9001;
let ore_over_nine_thousand = cipher.full_encrypt(over_nine_thousand.into()).unwrap();
```

Ciphertexts for the order-revealing and equality-revealing encryption schemes implement `Ord`, `Eq`, and the `Partial*` variants as appropriate.
Thus, you can just compare the outputs of the `encrypt` function like they were any other value:

```rust
# use cretrit::aes128v1::ore;
# let cipher = ore::Cipher::<4, 256>::new([0u8; 16]).unwrap();

# let ore_forty_two = cipher.full_encrypt(42u32.into()).unwrap();
# let ore_over_nine_thousand = cipher.full_encrypt(9001u32.into()).unwrap();

assert!(ore_forty_two != ore_over_nine_thousand);
assert!(ore_forty_two < ore_over_nine_thousand);
```

You can also serialise and deserialise ciphertexts to/from `u8` vectors, which allows you to store them in files, databases, etc.
A simple example of round-tripping a ciphertext:

```rust
// Pull in the necessary trait
use cretrit::SerializableCipherText;

# use cretrit::aes128v1::ore;
# let cipher = ore::Cipher::<4, 256>::new([0u8; 16]).unwrap();
# let ore_forty_two = cipher.full_encrypt(42u32.into()).unwrap();
# let ore_over_nine_thousand = cipher.full_encrypt(9001u32.into()).unwrap();

let v = ore_forty_two.to_vec();

// When deserialising a ciphertext, you need to specify the cipher parameters
// so that the types line up.
let new_forty_two = ore::CipherText::<4, 256>::from_slice(&v).unwrap();

// Once it's deserialised, it's back to its original form and ready to
// go!
assert!(new_forty_two == ore_forty_two);
assert!(new_forty_two != ore_over_nine_thousand);
assert!(new_forty_two < ore_over_nine_thousand);
```


# Terminology

To help make sense of everything, here's some of the terms that we use in the codebase and documentation.

* **Comparison-Revealing Encryption**: a generic encryption scheme which produces ciphertexts which can be compared against one another to determine a defined relationship between the plaintexts from which the ciphertexts were produced.
  Ideally, the ciphertexts do not reveal any other information about the two plaintexts or their relationship to each other.

* **Order-Revealing Encryption**: a form of comparison-revealing encryption, which produces ciphertexts which reveal the relative ordering of ciphertexts, without giving any indication of the actual value of the underlying plaintexts.
  This is done by revealing whether a ciphertext is less-than, equal-to, or greater-than any other ciphertext, which is all that is necessary to order any collection of ciphertexts.

* **Equality-Revealing Encryption**: a form or comparison-revealing encryption, which produces ciphertexts which reveal whether the plaintext value behind two ciphertexts are equal, or not.
  While order-revealing encryption can also be used to reveal equality, this form is useful when there is no well-defined ordering of a set of values, or you specifically do not which to reveal that ordering.
  The ciphertexts produced by equality-revealing encryption are also smaller than those produced by order-revealing encryption.

* **Cipher Suite**: a collection of cryptographic primitives which, in combination, are needed to perform the complete set of comparison-revealing encryption operations.
  Multiple cipher suites may be defined to upgrade security, or provide increased performance.

* **Cipher**: a combination of a cipher suite and comparison operator which, together, provide the ability to encrypt a plaintext into a particular comparison-revealing form.

* **Plaintext Block**: to keep ciphertext sizes under control, the Lewi-Wu scheme breaks a single large plaintext into smaller blocks.
  Each block can represent values of a certain range, and a single plaintext has a certain number of blocks.
  These parameters control the size and leakage of the corresponding ciphertext.


# Contributing

For general guidelines for contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).


# Licence

Unless otherwise stated, everything in this repo is covered by the following
licence statement (the MIT licence):

```text
    Copyright (C) 2022  Matt Palmer <matt@enquo.org>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
```
