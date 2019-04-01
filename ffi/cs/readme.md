# C# binding of BLS threshold signature library

# Installation Requirements

* Visual Studio 2017 or later
* C# 7.2 or later
* .NET Framework 4.5.2 or later

# How to build

```
md work
cd work
git clone https://github.com/herumi/cybozulib_ext
git clone https://github.com/herumi/mcl
git clone https://github.com/herumi/bls
cd bls
mklib dll
```

# How to build a sample

Open bls/ffi/cs/bls.sln and exec it.

* Remark. bls256 is obsolete. Please use bls.sln.

# class and API

## API

* `Init(int curveType = BN254);`
    * initialize this library with a curve `curveType`.
    * curveType = BN254 or BLS12_381
* `SecretKey ShareSecretKey(in SecretKey[] msk, in Id id);`
    * generate the shared secret key from a sequence of master secret keys msk and Id.
* `SecretKey RecoverSecretKey(in SecretKey[] secVec, in Id[] idVec);`
    * recover the secret key from a sequence of secret keys secVec and idVec.
* `PublicKey SharePublicKey(in PublicKey[] mpk, in Id id);`
    * generate the shared public key from a sequence of master public keys mpk and Id.
* `PublicKey RecoverPublicKey(in PublicKey[] pubVec, in Id[] idVec);`
    * recover the public key from a sequence of public keys pubVec and idVec.
* `Signature RecoverSign(in Signature[] sigVec, in Id[] idVec);`
    * recover the signature from a sequence of signatures siVec and idVec.

## Id

Identifier class

* `byte[] Serialize();`
    * serialize Id
* `void Deserialize(byte[] buf);`
    * deserialize from byte[] buf
* `bool IsEqual(in Id rhs);`
    * equality
* `void SetDecStr(string s);`
    * set by a decimal string s
* `void SetHexStr(string s);`
    * set by a hexadecimal string s
* `void SetInt(int x);`
    * set an integer x
* `string GetDecStr();`
    * get a decimal string
* `string GetHexStr();`
    * get a hexadecimal string

## SecretKey

* `byte[] Serialize();`
    * serialize SecretKey
* `void Deserialize(byte[] buf);`
    * deserialize from byte[] buf
* `bool IsEqual(in SecretKey rhs);`
    * equality
* `string GetDecStr();`
    * get a decimal string
* `string GetHexStr();`
    * get a hexadecimal string
* `void Add(in SecretKey rhs);`
    * add a secret key rhs
* `void SetByCSPRNG();`
    * set a secret key by cryptographically secure pseudo random number generator
* `void SetHashOf(string s);`
    * set a secret key by a hash of string s
* `PublicKey GetPublicKey();`
    * get the corresponding public key to a secret key
* `Signature Sign(string m);`
    * sign a string m
* `Signature GetPop();`
    * get a PoP (Proof Of Posession) for a secret key

## PublicKey

* `byte[] Serialize();`
    * serialize PublicKey
* `void Deserialize(byte[] buf);`
    * deserialize from byte[] buf
* `bool IsEqual(in PublicKey rhs);`
    * equality
* `void Add(in PublicKey rhs);`
    * add a public key rhs
* `string GetDecStr();`
    * get a decimal string
* `string GetHexStr();`
    * get a hexadecimal string
* `bool Verify(in Signature sig, string m);`
    * verify the validness of the sig with m
* `bool VerifyPop(in Signature pop);`
    * verify the validness of PoP

## Signature

* `byte[] Serialize();`
    * serialize Signature
* `void Deserialize(byte[] buf);`
    * deserialize from byte[] buf
* `bool IsEqual(in Signature rhs);`
    * equality
* `void Add(in Signature rhs);`
    * add a signature key rhs
* `string GetDecStr();`
    * get a decimal string
* `string GetHexStr();`
    * get a hexadecimal string

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)
