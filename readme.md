[![Build Status](https://travis-ci.org/herumi/bls.png)](https://travis-ci.org/herumi/bls)

# BLS threshold signature

An implementation of BLS threshold signature

# Installation Requirements

Create a working directory (e.g., work) and clone the following repositories.
```
mkdir work
cd work
git clone git://github.com/herumi/mcl.git
git clone git://github.com/herumi/bls.git
git clone git://github.com/herumi/cybozulib_ext ; for only Windows
```

# News
* (Break backward compatibility) The suffix `_dy` of library name is removed and bls\*.a requires libmcl.so set LD_LIBRARY_PATH to the directory.
* -tags option for Go bindings
    * -tags bn256
    * -tags bn384\_256
    * -tags bn384 ; default mode
* Support swap of G1 and G2
    * `make BLS_SWAP_G=1` then G1 is assigned to PublicKey and G2 is assigned to Signature.
    * golang binding does not support this feature yet.
* Build option without GMP
    * `make MCL_USE_GMP=0`
* Build option without OpenSSL
    * `make MCL_USE_OPENSSL=0`
* Build option to specify `mcl` directory
    * `make MCL_DIR=<mcl directory>`

* (old) libbls.a for C++ interface(bls/bls.hpp) is removed
Link `lib/libbls256.a` or `lib/libbls384.a` to use `bls/bls.hpp` according to MCLBN_FP_UNIT_SIZE = 4 or 6.

# Build and test for Linux
To make and test, run
```
cd bls
make test
```
To make sample programs, run
```
make sample_test
```

# Build and test for Windows
1) make static library and use it
```
mklib
mk -s test\bls_c384_test.cpp
bin\bls_c384_test.exe
```

2) make dynamic library and use it
```
mklib dll
mk -d test\bls_c384_test.cpp
bin\bls_c384_test.exe
```

# Library
* libbls256.a/libbls256.so ; for BN254 compiled with MCLBN_FP_UNIT_SIZE=4
* libbls384.a/libbls384.so ; for BN254/BN381_1/BLS12_381 compiled with MCLBN_FP_UNIT_SIZE=6
* libbls384_256.a/libbls384_256.so ; for BN254/BLS12_381 compiled with MCLBN_FP_UNIT_SIZE=6 and MCLBN_FR_UNIT_SIZE=4

See `mcl/include/curve_type.h` for curve parameter

# API

## Basic API

BLS signature
```
e : G2 x G1 -> Fp12 ; optimal ate pairing over BN curve
Q in G2 ; fixed global parameter
H : {str} -> G1
s in Fr: secret key
sQ in G2; public key
s H(m) in G1; signature of m
verify ; e(sQ, H(m)) = e(Q, s H(m))
```

```
void bls::init();
```

Initialize this library. Call this once to use the other api.

```
void SecretKey::init();
```

Initialize the instance of SecretKey. `s` is a random number.

```
void SecretKey::getPublicKey(PublicKey& pub) const;
```

Get public key `sQ` for the secret key `s`.

```
void SecretKey::sign(Sign& sign, const std::string& m) const;
```

Make sign `s H(m)` from message m.

```
bool Sign::verify(const PublicKey& pub, const std::string& m) const;
```

Verify sign with pub and m and return true if it is valid.

```
e(sQ, H(m)) == e(Q, s H(m))
```

### Secret Sharing API

```
void SecretKey::getMasterSecretKey(SecretKeyVec& msk, size_t k) const;
```

Prepare k-out-of-n secret sharing for the secret key.
`msk[0]` is the original secret key `s` and `msk[i]` for i > 0 are random secret key.

```
void SecretKey::set(const SecretKeyVec& msk, const Id& id);
```

Make secret key f(id) from msk and id where f(x) = msk[0] + msk[1] x + ... + msk[k-1] x^{k-1}.

You can make a public key `f(id)Q` from each secret key f(id) for id != 0 and sign a message.

```
void Sign::recover(const SignVec& signVec, const IdVec& idVec);
```

Collect k pair of sign `f(id) H(m)` and `id` for a message m and recover the original signature `s H(m)` for the secret key `s`.

### PoP (Proof of Possesion)

```
void SecretKey::getPop(Sign& pop) const;
```

Sign pub and make a pop `s H(sQ)`

```
bool Sign::verify(const PublicKey& pub) const;
```

Verify a public key by pop.

# Check the order of a point

deserializer functions check whether a point has correct order and
the cost is heavy for especially G2.
If you do not want to check it, then call
```
void blsSignatureVerifyOrder(false);
void blsPublicKeyVerifyOrder(false);
```

cf. subgroup attack

# Go
```
make test_go
```

# WASM(WebAssembly)
```
mkdir ../bls-wasm
make bls-wasm
```
see [BLS signature demo on browser](https://herumi.github.io/bls-wasm/bls-demo.html)

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)
