[![Build Status](https://travis-ci.org/herumi/bls.png)](https://travis-ci.org/herumi/bls)

# BLS threshold signature

An implementation of BLS threshold signature

# Installation Requirements

Create a working directory (e.g., work) and clone the following repositories.
```
mkdir work
cd work
git clone git://github.com/herumi/xbyak.git
git clone git://github.com/herumi/cybozulib.git
git clone git://github.com/herumi/mcl.git
git clone git://github.com/herumi/bls.git
git clone git://github.com/herumi/cybozulib_ext ; for only Windows
```

# Build and test for Linux
Specifiy UNIT=4 or 6 always to make.
To make lib/libbls.a and test, run
```
cd bls
make test UNIT=4
```
To make sample programs, run
```
make sample_test
```

# Build and test for Windows
```
cd mcl
mklib
cd ..\bls
mklib
mk test\bls_test.cpp
bls_test.exe
```

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

# Go
```
make run_go
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)
