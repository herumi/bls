#pragma once
/**
	@file
	@brief BLS threshold signature on BN curve
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <mcl/bn.h>
#include <bls/bls.h>
#include <vector>
#include <string>
#include <iosfwd>
#include <stdint.h>

#ifdef _MSC_VER
	#pragma comment(lib, "bls.lib")
#endif

namespace bls {

// same value with IoMode of mcl/op.hpp
enum {
	IoBin = 2, // binary number
	IoDec = 10, // decimal number
	IoHex = 16, // hexadecimal number
	IoFixedByteSeq = 512 // fixed byte representation
};

namespace impl {

struct SecretKey;
struct PublicKey;
struct Signature;
struct Id;

} // bls::impl

/*
	BLS signature
	e : G2 x G1 -> Fp12
	Q in G2 ; fixed global parameter
	H : {str} -> G1
	s : secret key
	sQ ; public key
	s H(m) ; signature of m
	verify ; e(sQ, H(m)) = e(Q, s H(m))
*/

/*
	initialize this library
	call this once before using the other method
	@param curve [in] type of curve
	@param maxUnitSize [in] 4 or 6 (specify same value used in compiling for validation)
	@note init() is not thread safe
*/
void init(int curve = mclBn_CurveFp254BNb, int maxUnitSize = MCLBN_FP_UNIT_SIZE);
size_t getOpUnitSize();
void getCurveOrder(std::string& str);
void getFieldOrder(std::string& str);

class SecretKey;
class PublicKey;
class Signature;
class Id;

/*
	the value of secretKey and Id must be less than
	r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
	sizeof(uint64_t) * keySize byte
*/
const size_t keySize = MCLBN_FP_UNIT_SIZE;

typedef std::vector<SecretKey> SecretKeyVec;
typedef std::vector<PublicKey> PublicKeyVec;
typedef std::vector<Signature> SignatureVec;
typedef std::vector<Id> IdVec;

class Id {
	blsId self_;
	friend class PublicKey;
	friend class SecretKey;
	template<class T, class G> friend struct WrapArray;
	impl::Id& getInner() { return *reinterpret_cast<impl::Id*>(this); }
	const impl::Id& getInner() const { return *reinterpret_cast<const impl::Id*>(this); }
public:
	Id(unsigned int id = 0);
	bool operator==(const Id& rhs) const;
	bool operator!=(const Id& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const Id& id);
	friend std::istream& operator>>(std::istream& is, Id& id);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	bool isZero() const;
	/*
		set p[0, .., keySize)
		@note the value must be less than r
	*/
	void set(const uint64_t *p);
	// bufSize is truncted/zero extended to keySize
	void setLittleEndian(const void *buf, size_t bufSize);
};

/*
	s ; secret key
*/
class SecretKey {
	blsSecretKey self_;
	template<class T, class G> friend struct WrapArray;
	impl::SecretKey& getInner() { return *reinterpret_cast<impl::SecretKey*>(this); }
	const impl::SecretKey& getInner() const { return *reinterpret_cast<const impl::SecretKey*>(this); }
public:
	SecretKey() : self_() {}
	bool operator==(const SecretKey& rhs) const;
	bool operator!=(const SecretKey& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const SecretKey& sec);
	friend std::istream& operator>>(std::istream& is, SecretKey& sec);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	/*
		initialize secretKey with random number and set id = 0
	*/
	void init();
	/*
		set secretKey with p[0, .., keySize) and set id = 0
		@note the value must be less than r
	*/
	void set(const uint64_t *p);
	// bufSize is truncted/zero extended to keySize
	void setLittleEndian(const void *buf, size_t bufSize);
	// set hash of buf
	void setHashOf(const void *buf, size_t bufSize);
	void getPublicKey(PublicKey& pub) const;
	// constant time sign
	void sign(Signature& sig, const std::string& m) const;
	/*
		make Pop(Proof of Possesion)
		pop = prv.sign(pub)
	*/
	void getPop(Signature& pop) const;
	/*
		make [s_0, ..., s_{k-1}] to prepare k-out-of-n secret sharing
	*/
	void getMasterSecretKey(SecretKeyVec& msk, size_t k) const;
	/*
		set a secret key for id > 0 from msk
	*/
	void set(const SecretKeyVec& msk, const Id& id)
	{
		set(msk.data(), msk.size(), id);
	}
	/*
		recover secretKey from k secVec
	*/
	void recover(const SecretKeyVec& secVec, const IdVec& idVec);
	/*
		add secret key
	*/
	void add(const SecretKey& rhs);

	// the following methods are for C api
	/*
		the size of msk must be k
	*/
	void set(const SecretKey *msk, size_t k, const Id& id);
	void recover(const SecretKey *secVec, const Id *idVec, size_t n);
};

/*
	sQ ; public key
*/
class PublicKey {
	blsPublicKey self_;
	friend class SecretKey;
	friend class Signature;
	template<class T, class G> friend struct WrapArray;
	impl::PublicKey& getInner() { return *reinterpret_cast<impl::PublicKey*>(this); }
	const impl::PublicKey& getInner() const { return *reinterpret_cast<const impl::PublicKey*>(this); }
public:
	PublicKey() : self_() {}
	bool operator==(const PublicKey& rhs) const;
	bool operator!=(const PublicKey& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const PublicKey& pub);
	friend std::istream& operator>>(std::istream& is, PublicKey& pub);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	/*
		set public for id from mpk
	*/
	void set(const PublicKeyVec& mpk, const Id& id)
	{
		set(mpk.data(), mpk.size(), id);
	}
	/*
		recover publicKey from k pubVec
	*/
	void recover(const PublicKeyVec& pubVec, const IdVec& idVec);
	/*
		add public key
	*/
	void add(const PublicKey& rhs);

	// the following methods are for C api
	void set(const PublicKey *mpk, size_t k, const Id& id);
	void recover(const PublicKey *pubVec, const Id *idVec, size_t n);
};

/*
	s H(m) ; signature
*/
class Signature {
	blsSignature self_;
	friend class SecretKey;
	template<class T, class G> friend struct WrapArray;
	impl::Signature& getInner() { return *reinterpret_cast<impl::Signature*>(this); }
	const impl::Signature& getInner() const { return *reinterpret_cast<const impl::Signature*>(this); }
public:
	Signature() : self_() {}
	bool operator==(const Signature& rhs) const;
	bool operator!=(const Signature& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const Signature& s);
	friend std::istream& operator>>(std::istream& is, Signature& s);
	void getStr(std::string& str, int ioMode = 0) const;
	void setStr(const std::string& str, int ioMode = 0);
	bool verify(const PublicKey& pub, const std::string& m) const;
	/*
		verify self(pop) with pub
	*/
	bool verify(const PublicKey& pub) const;
	/*
		recover sig from k sigVec
	*/
	void recover(const SignatureVec& sigVec, const IdVec& idVec);
	/*
		add signature
	*/
	void add(const Signature& rhs);

	// the following methods are for C api
	void recover(const Signature* sigVec, const Id *idVec, size_t n);
};

/*
	make master public key [s_0 Q, ..., s_{k-1} Q] from msk
*/
inline void getMasterPublicKey(PublicKeyVec& mpk, const SecretKeyVec& msk)
{
	const size_t n = msk.size();
	mpk.resize(n);
	for (size_t i = 0; i < n; i++) {
		msk[i].getPublicKey(mpk[i]);
	}
}

/*
	make pop from msk and mpk
*/
inline void getPopVec(SignatureVec& popVec, const SecretKeyVec& msk)
{
	const size_t n = msk.size();
	popVec.resize(n);
	for (size_t i = 0; i < n; i++) {
		msk[i].getPop(popVec[i]);
	}
}

inline Signature operator+(const Signature& a, const Signature& b) { Signature r(a); r.add(b); return r; }
inline PublicKey operator+(const PublicKey& a, const PublicKey& b) { PublicKey r(a); r.add(b); return r; }
inline SecretKey operator+(const SecretKey& a, const SecretKey& b) { SecretKey r(a); r.add(b); return r; }

} //bls
