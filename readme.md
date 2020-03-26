[![Build Status](https://travis-ci.org/herumi/bls.png)](https://travis-ci.org/herumi/bls)

# BLS threshold signature

An implementation of BLS threshold signature

# Support architectures

* Windows Visual Studio / MSYS2(MinGW-w64)
* Linux
* macOS
* Android
* iOS
* WebAssembly

# News
- 2020/Mar/26 : DST of hash-to-curve of [mcl](https://github.com/herumi/mcl) is changed, so the output has also changed for `BLS_ETH_MODE_DRAFT_06`.
- 2020/Mar/15 : `blsSetETHmode()` supports `BLS_ETH_MODE_DRAFT_06` defined at [draft-irtf-cfrg-hash-to-curve](https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.txt) at March 2020. But it has not yet fully tested.

This library supports the new BLS Signatures specified at [Ethereum 2.0 Phase 0](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures).

bls.h | eth2.0 spec name|
------|-----------------|
blsSign|Sign|
blsVerify|Verify|
blsAggregateSignature|Aggregate|
blsFastAggregateVerify|FastAggregateVerify|
blsAggregateVerifyNoCheck|AggregateVerify|

## Support language bindings

language|ETH2.0 spec(PublicKey=G1)|old(PublicKey = G2)|
--|--|--|
Go|[bls-eth-go-binary](https://github.com/herumi/bls-eth-go-binary)|[bls-go-binary](https://github.com/herumi/bls-go-binary)|
WebAssembly(Node.js)|[bls-eth-wasm](https://github.com/herumi/bls-eth-wasm)|[bls-wasm](https://github.com/herumi/bls-wasm)|
Rust|[bls-eth-rust](https://github.com/herumi/bls-eth-rust)|-|


## APIs for the latest eth2.0-specs

### Header files

```
#include <mcl/bn384_256.h>
#include <bls/bls.h>
```

`bn384_256.h` is for 384-bit `p` and 256-bit `r`, where the elliptic curve is defined over `Fp` and the order of `G1` and `G2` is `r`.

### Libraries

The compiled static libraries for {linux, windows, darwin}/amd64 and android/{arm64-v8a, armeabi-v7a}
are provided at [bls-eth-go-binary/bls/lib](https://github.com/herumi/bls-eth-go-binary/tree/master/bls/lib)

On Linux, macOS

```
make CXX=clang++-8 lib/libbls384_256.a BLS_ETH=1
```

On Windows

```
mklib eth
```
### Initialization

```
// init library at once before calling the other apis
blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);

// use the latest eth2.0 spec
blsSetETHmode(BLS_ETH_MODE_LATEST);
```

### Setup

Init SecretKey `sec` and create PublicKey `pub`.
```
blsSecretKey sec;
blsPublicKey pub;

// init SecretKey sec by random number
blsSecretKeySetByCSPRNG(&sec);

// get PublicKey pub from SecretKey sec
blsGetPublicKey(&pub, &sec);
```

### Sign

Make Signature `sig` of Message `msg[0..msgSize-1]` by SecretKey `sec`.
```
blsSignature sig;
char msg[] = "hello";
const size_t msgSize = strlen(msg);

blsSign(&sig, &sec, msg, msgSize);
```

`msg` may contain `\x00` if the correct `msgSize` is specified.

### Verify

Verify Signature `sig` of Message `msg[0..msgSize-1]` by PublicKey `pub`.
```
// return 1 if it is valid else 0
int blsVerify(&sig, &pub, msg, msgSize);
```

### Aggregate Signature

Aggregate Signatures `sigVec[0]`, ..., `sigVec[n-1]` to `aggSig`.

```
// return 1 if it is valid else 0
void blsAggregateSignature(
  blsSignature *aggSig,
  const blsSignature *sigVec,
  mclSize n
);
```

### FastAggregateVerify

Verify Signature `sig` of Message `msg[0..msgSize-1]` by `pubVec[0]`, ..., `pubVec[n-1]`.

```
int blsFastAggregateVerify(
  const blsSignature *sig,
  const blsPublicKey *pubVec,
  mclSize n,
  const void *msg,
  mclSize msgSize
);
```

### AggregateVerify

- `pubVec` is `n` array of PublicKey
- `msgVec` is `n * msgSize`-byte array, which concatenates `n`-byte messages of length `msgSize`.

Verify Signature `sig` of (Message `msgVec[msgSize * i..msgSize * (i+1)-1]` and `pubVec[i]`) for i = `0`, ..., `n-1`.

```
int blsAggregateVerifyNoCheck(
  const blsSignature *sig,
  const blsPublicKey *pubVec,
  const void *msgVec,
  mclSize msgSize,
  mclSize n
);
```

REMARK : `blsAggregateVerifyNoCheck` does not check
- `sig` has the correct order
- every `n`-byte messages of length `msgSize` are different each other

Check them at the caller if necessary.

### Check order

Check whether `sig` and `pub` have the correct order `r`.

```
// return 1 if it is valid else 0
int blsSignatureIsValidOrder(const blsSignature *sig);
int blsPublicKeyIsValidOrder(const blsPublicKey *pub);
```

# End for the latest eth2.0-spec
<hr>

# Support languages

* C#; in ffi/cs

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
* disabled to check the order in setStr/deserialize. call once `blsSignatureVerifyOrder(1)` or `blsPublicKeyVerifyOrder(1)` to check it.
* add uncompressed function to PublicKey and Sign
* add blsSignHashWithDomain, blsVerifyHashWithDomain(see (Ethereum 2.0 spec mode)[https://github.com/herumi/bls/#ethereum-20-spec-mode])
* rename blsGetGeneratorOfG{1 or 2} to blsGetGeneratorOfPublicKey
* add blsSetETHserialization(1) to use ETH serialization for BLS12-381
* Support swap of G1 and G2 for Go (-tags bn384_256_swapg)
* blsInit() is not thread safe (pthread is not used)
* -tags option for Go bindings is always necessary
    * use -tags bn384\_256 for BLS12-381
* support Android
* (Break backward compatibility) The suffix `_dy` of library name is removed and bls\*.a requires libmcl.so set LD_LIBRARY_PATH to the directory.
* -tags option for Go bindings
    * -tags bn256
    * -tags bn384\_256
    * -tags bn384
* Support swap of G1 and G2
    * `make BLS_SWAP_G=1` then G1 is assigned to PublicKey and G2 is assigned to Signature.
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

# Build for Android
see [readme.md](ffi/android/readme.md)

# Build for iOS

```
cd bls
make gomobile
```

# Swap G1 and G2
If you want to swap G1 and G2 for PublicKey and Signature, then type as the followings:
```
make clean
make BLS_SWAP_G=1
make test_go_swapg ; test for cgo
```

Remark:
- The library built with BLS_SWAP_G is not compatible with the library built without BLS_SWAP_G.
- Define `-DBLS_SWAP_G' before including `bls/bn.h`.

# The older Ethereum 2.0 spec mode
This mode will be removed in the future.
```
make clean
make BLS_ETH=1 bin/libbls384_256.a
```

## APIs for sign/verify
`uint8_t hashWithDomain[40]` in the following apis means a structure of 32 bytes msg and 8 bytes domain.

```
struct Message {
  uint8_t hash[32];
  uint8_t domain[8];
};
```

### Sign `hashWithDomain` by `sec` and create `sig`
```
int blsSignHashWithDomain(blsSignature *sig, const blsSecretKey *sec, const unsigned char hashWithDomain[40]);
```
return 0 if sccess else -1

### Verify `sig` for `hashWithDomain` by `pub`
```
int blsVerifyHashWithDomain(const blsSignature *sig, const blsPublicKey *pub, const unsigned char hashWithDomain[40]);
```
return 1 if valid else 0

### Verify `aggSig` for `{hashWithDomain[i]}` by `{pubVec[i]}`

`aggSig` is aggregated signature of `{sig[i]}` corresponding to `{pubVec[i]}`.

```
int blsVerifyAggregatedHashWithDomain(const blsSignature *aggSig, const blsPublicKey *pubVec, const unsigned char hashWithDomain[][40], mclSize n);
```
return 1 if valid else 0

# Library
* libbls256.a/libbls256.so ; for BN254 compiled with MCLBN_FP_UNIT_SIZE=4
* libbls384.a/libbls384.so ; for BN254/BN381_1/BLS12_381 compiled with MCLBN_FP_UNIT_SIZE=6
* libbls384_256.a/libbls384_256.so ; for BN254/BLS12_381 compiled with MCLBN_FP_UNIT_SIZE=6 and MCLBN_FR_UNIT_SIZE=4
  - precompiled static library is provided at [bls-go-binary](https://github.com/herumi/bls-go-binary/)

See `mcl/include/curve_type.h` for curve parameter

## Remark for static library
If there are both a shared library both and static library having the same name in the same directory, then the shared library is linked.
So if you want to link a static library, then remove the shared library in the directory.

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

### C

```
blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR); // use BLS12-381
blsSignatureVerifyOrder(0); // disable to check the order of a point in deserializing
blsPublicKeyVerifyOrder(0);
blsSetETHserialization(1); // obey ETH serialization

```

### C++

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

### PoP (Proof of Possession)

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

# WASM(WebAssembly)
* see [BLS signature demo on browser](https://herumi.github.io/bls-wasm/bls-demo.html)

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)
