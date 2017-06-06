#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <iosfwd>
#include <stdint.h>
#include <memory.h>
#include "../mcl/src/bn_c_impl.hpp"
#define BLS_DLL_EXPORT

#include <bls/bls.h>
/////////////////////////////////////////////////////////////
namespace bls2 {

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

} // bls2::impl

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

} //bls2
////////////////////////////////////////////////////////////////
typedef std::vector<Fr> FrVec;

static cybozu::RandomGenerator& getRG()
{
	static cybozu::RandomGenerator rg;
	return rg;
}

static const std::vector<Fp6> *g_pQcoeff;
static const G2 *g_pQ;

namespace bls2 {

static const G2& getQ() { return *g_pQ; }
static const std::vector<Fp6>& getQcoeff() { return *g_pQcoeff; }

static void HashAndMapToG1(G1& P, const std::string& m)
{
	Fp t;
	t.setHashOf(m);
	BN::mapToG1(P, t);
}

template<class T, class G, class Vec>
void evalPoly(G& y, const T& x, const Vec& c)
{
	if (c.size() < 2) throw cybozu::Exception("bls:evalPoly:bad size") << c.size();
	y = c[c.size() - 1];
	for (int i = (int)c.size() - 2; i >= 0; i--) {
		G::mul(y, y, x);
		G::add(y, y, c[i]);
	}
}

template<class T, class G>
struct WrapArray {
	const T *v;
	size_t k;
	WrapArray(const T *v, size_t k) : v(v), k(k) {}
	const G& operator[](size_t i) const
	{
		return v[i].getInner().get();
	}
	size_t size() const { return k; }
};

struct Polynomial {
	FrVec c; // f[x] = sum_{i=0}^{k-1} c[i] x^i
	void init(const Fr& s, int k)
	{
		if (k < 2) throw cybozu::Exception("bls:Polynomial:init:bad k") << k;
		c.resize(k);
		c[0] = s;
		for (size_t i = 1; i < c.size(); i++) {
			c[i].setRand(getRG());
		}
	}
	// y = f(id)
	void eval(Fr& y, const Fr& id) const
	{
		if (id.isZero()) throw cybozu::Exception("bls:Polynomial:eval:id is zero");
		evalPoly(y, id, c);
	}
};

namespace impl {

struct Id {
	Fr v;
	const Fr& get() const { return v; }
};

struct SecretKey {
	Fr s;
	const Fr& get() const { return s; }
};

struct Signature {
	G1 sHm; // s Hash(m)
	const G1& get() const { return sHm; }
};

struct PublicKey {
	G2 sQ;
	const G2& get() const { return sQ; }
	void getStr(std::string& str) const
	{
		sQ.getStr(str, mcl::IoArrayRaw);
	}
};

} // mcl::bls::impl

/*
	recover f(0) by { (x, y) | x = S[i], y = f(x) = vec[i] }
*/
template<class G, class V1, class V2>
void LagrangeInterpolation(G& r, const V1& vec, const V2& S)
{
	/*
		delta_{i,S}(0) = prod_{j != i} S[j] / (S[j] - S[i]) = a / b
		where a = prod S[j], b = S[i] * prod_{j != i} (S[j] - S[i])
	*/
	const size_t k = S.size();
	if (vec.size() != k) throw cybozu::Exception("bls:LagrangeInterpolation:bad size") << vec.size() << k;
	if (k < 2) throw cybozu::Exception("bls:LagrangeInterpolation:too small size") << k;
	FrVec delta(k);
	Fr a = S[0];
	for (size_t i = 1; i < k; i++) {
		a *= S[i];
	}
	for (size_t i = 0; i < k; i++) {
		Fr b = S[i];
		for (size_t j = 0; j < k; j++) {
			if (j != i) {
				Fr v = S[j] - S[i];
				if (v.isZero()) throw cybozu::Exception("bls:LagrangeInterpolation:S has same id") << i << j;
				b *= v;
			}
		}
		delta[i] = a / b;
	}

	/*
		f(0) = sum_i f(S[i]) delta_{i,S}(0)
	*/
	r.clear();
	G t;
	for (size_t i = 0; i < delta.size(); i++) {
		G::mul(t, vec[i], delta[i]);
		r += t;
	}
}

template<class T>
std::ostream& writeAsHex(std::ostream& os, const T& t)
{
	std::string str;
	t.getStr(str, mcl::IoHexPrefix);
	return os << str;
}

Id::Id(unsigned int id)
{
	getInner().v = id;
}

bool Id::operator==(const Id& rhs) const
{
	return getInner().v == rhs.getInner().v;
}

std::ostream& operator<<(std::ostream& os, const Id& id)
{
	return writeAsHex(os, id.getInner().v);
}

std::istream& operator>>(std::istream& is, Id& id)
{
	return is >> id.getInner().v;
}
void Id::getStr(std::string& str, int ioMode) const
{
	getInner().v.getStr(str, ioMode);
}
void Id::setStr(const std::string& str, int ioMode)
{
	getInner().v.setStr(str, ioMode);
}

bool Id::isZero() const
{
	return getInner().v.isZero();
}

void Id::set(const uint64_t *p)
{
	getInner().v.setArrayMask(p, keySize);
}

void Id::setLittleEndian(const void *buf, size_t bufSize)
{
	getInner().v.setArrayMask((const char *)buf, bufSize);
}

bool Signature::operator==(const Signature& rhs) const
{
	return getInner().sHm == rhs.getInner().sHm;
}

std::ostream& operator<<(std::ostream& os, const Signature& s)
{
	return writeAsHex(os, s.getInner().sHm);
}

std::istream& operator>>(std::istream& os, Signature& s)
{
	return os >> s.getInner().sHm;
}
void Signature::getStr(std::string& str, int ioMode) const
{
	getInner().sHm.getStr(str, ioMode);
}
void Signature::setStr(const std::string& str, int ioMode)
{
	getInner().sHm.setStr(str, ioMode);
}

bool Signature::verify(const PublicKey& pub, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m); // Hm = Hash(m)
#if 1
	/*
		e(P1, Q1) == e(P2, Q2)
		<=> finalExp(ML(P1, Q1)) == finalExp(ML(P2, Q2))
		<=> finalExp(ML(P1, Q1) / ML(P2, Q2)) == 1
		<=> finalExp(ML(P1, Q1) * ML(-P2, Q2)) == 1
		2.1Mclk => 1.5Mclk
	*/
	Fp12 e;
	std::vector<Fp6> Q2coeff;
	BN::precomputeG2(Q2coeff, pub.getInner().sQ);
	BN::precomputedMillerLoop2(e, getInner().sHm, getQcoeff(), -Hm, Q2coeff);
	BN::finalExp(e, e);
	return e.isOne();
#else
	Fp12 e1, e2;
	BN::pairing(e1, getInner().sHm, getQ()); // e(s Hm, Q)
	BN::pairing(e2, Hm, pub.getInner().sQ); // e(Hm, sQ)
	return e1 == e2;
#endif
}

bool Signature::verify(const PublicKey& pub) const
{
	std::string str;
	pub.getInner().sQ.getStr(str);
	return verify(pub, str);
}

void Signature::recover(const SignatureVec& sigVec, const IdVec& idVec)
{
	if (sigVec.size() != idVec.size()) throw cybozu::Exception("Signature:recover:bad size") << sigVec.size() << idVec.size();
	recover(sigVec.data(), idVec.data(), sigVec.size());
}

void Signature::recover(const Signature* sigVec, const Id *idVec, size_t n)
{
	WrapArray<Signature, G1> signW(sigVec, n);
	WrapArray<Id, Fr> idW(idVec, n);
	LagrangeInterpolation(getInner().sHm, signW, idW);
}

void Signature::add(const Signature& rhs)
{
	getInner().sHm += rhs.getInner().sHm;
}

bool PublicKey::operator==(const PublicKey& rhs) const
{
	return getInner().sQ == rhs.getInner().sQ;
}

std::ostream& operator<<(std::ostream& os, const PublicKey& pub)
{
	return writeAsHex(os, pub.getInner().sQ);
}

std::istream& operator>>(std::istream& is, PublicKey& pub)
{
	return is >> pub.getInner().sQ;
}

void PublicKey::getStr(std::string& str, int ioMode) const
{
	getInner().sQ.getStr(str, ioMode);
}
void PublicKey::setStr(const std::string& str, int ioMode)
{
	getInner().sQ.setStr(str, ioMode);
}
void PublicKey::set(const PublicKey *mpk, size_t k, const Id& id)
{
	WrapArray<PublicKey, G2> w(mpk, k);
	evalPoly(getInner().sQ, id.getInner().v, w);
}

void PublicKey::recover(const PublicKeyVec& pubVec, const IdVec& idVec)
{
	if (pubVec.size() != idVec.size()) throw cybozu::Exception("PublicKey:recover:bad size") << pubVec.size() << idVec.size();
	recover(pubVec.data(), idVec.data(), pubVec.size());
}
void PublicKey::recover(const PublicKey *pubVec, const Id *idVec, size_t n)
{
	WrapArray<PublicKey, G2> pubW(pubVec, n);
	WrapArray<Id, Fr> idW(idVec, n);
	LagrangeInterpolation(getInner().sQ, pubW, idW);
}

void PublicKey::add(const PublicKey& rhs)
{
	getInner().sQ += rhs.getInner().sQ;
}

bool SecretKey::operator==(const SecretKey& rhs) const
{
	return getInner().s == rhs.getInner().s;
}

std::ostream& operator<<(std::ostream& os, const SecretKey& sec)
{
	return writeAsHex(os, sec.getInner().s);
}

std::istream& operator>>(std::istream& is, SecretKey& sec)
{
	return is >> sec.getInner().s;
}
void SecretKey::getStr(std::string& str, int ioMode) const
{
	getInner().s.getStr(str, ioMode);
}
void SecretKey::setStr(const std::string& str, int ioMode)
{
	getInner().s.setStr(str, ioMode);
}

void SecretKey::init()
{
	getInner().s.setRand(getRG());
}

void SecretKey::set(const uint64_t *p)
{
	getInner().s.setArrayMask(p, keySize);
}
void SecretKey::setLittleEndian(const void *buf, size_t bufSize)
{
	getInner().s.setArrayMask((const char *)buf, bufSize);
}
void SecretKey::setHashOf(const void *buf, size_t bufSize)
{
	getInner().s.setHashOf(buf, bufSize);
}

void SecretKey::getPublicKey(PublicKey& pub) const
{
	G2::mul(pub.getInner().sQ, getQ(), getInner().s);
}

void SecretKey::sign(Signature& sig, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m);
//	G1::mul(sig.getInner().sHm, Hm, getInner().s);
	G1::mulCT(sig.getInner().sHm, Hm, getInner().s);
}

void SecretKey::getPop(Signature& pop) const
{
	PublicKey pub;
	getPublicKey(pub);
	std::string m;
	pub.getInner().sQ.getStr(m);
	sign(pop, m);
}

void SecretKey::getMasterSecretKey(SecretKeyVec& msk, size_t k) const
{
	if (k <= 1) throw cybozu::Exception("bls:SecretKey:getMasterSecretKey:bad k") << k;
	msk.resize(k);
	msk[0] = *this;
	for (size_t i = 1; i < k; i++) {
		msk[i].init();
	}
}

void SecretKey::set(const SecretKey *msk, size_t k, const Id& id)
{
	WrapArray<SecretKey, Fr> w(msk, k);
	evalPoly(getInner().s, id.getInner().v, w);
}

void SecretKey::recover(const SecretKeyVec& secVec, const IdVec& idVec)
{
	if (secVec.size() != idVec.size()) throw cybozu::Exception("SecretKey:recover:bad size") << secVec.size() << idVec.size();
	recover(secVec.data(), idVec.data(), secVec.size());
}
void SecretKey::recover(const SecretKey *secVec, const Id *idVec, size_t n)
{
	WrapArray<SecretKey, Fr> secW(secVec, n);
	WrapArray<Id, Fr> idW(idVec, n);
	LagrangeInterpolation(getInner().s, secW, idW);
}

void SecretKey::add(const SecretKey& rhs)
{
	getInner().s += rhs.getInner().s;
}

} // bls2
////////////////////////////////////////////////////////////////

size_t checkAndCopy(char *buf, size_t maxBufSize, const std::string& s)
{
	if (s.size() > maxBufSize + 1) {
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	buf[s.size()] = '\0';
	return s.size();
}

int blsInit(int curve, int maxUnitSize)
	try
{
	if (mclBn_init(curve, maxUnitSize) != 0) return -1;
	static G2 Q;
	if (curve == mclBn_CurveFp254BNb) {
		Q.set(
			Fp2("12723517038133731887338407189719511622662176727675373276651903807414909099441", "4168783608814932154536427934509895782246573715297911553964171371032945126671"),
			Fp2("13891744915211034074451795021214165905772212241412891944830863846330766296736", "7937318970632701341203597196594272556916396164729705624521405069090520231616")
		);
	} else {
		BN::mapToG2(Q, 1);
	}
	static std::vector<Fp6> Qcoeff;

	BN::precomputeG2(Qcoeff, Q);
	g_pQ = &Q;
	g_pQcoeff = &Qcoeff;
	return 0;
} catch (std::exception&) {
	return -1;
}
size_t blsGetOpUnitSize()
{
	return Fp::getUnitSize() * sizeof(mcl::fp::Unit) / sizeof(uint64_t);
}

int blsGetCurveOrder(char *buf, size_t maxBufSize)
	try
{
	std::string s;
	Fr::getModulo(s);
	return (int)checkAndCopy(buf, maxBufSize, s);
} catch (std::exception&) {
	return 0;
}

int blsGetFieldOrder(char *buf, size_t maxBufSize)
	try
{
	std::string s;
	Fp::getModulo(s);
	return (int)checkAndCopy(buf, maxBufSize, s);
} catch (std::exception&) {
	return 0;
}


void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec)
{
	((const bls2::SecretKey*)sec)->getPublicKey(*(bls2::PublicKey*)pub);
}
void blsSign(blsSignature *sig, const blsSecretKey *sec, const char *m, size_t size)
{
	((const bls2::SecretKey*)sec)->sign(*(bls2::Signature*)sig, std::string(m, size));
}
int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id)
	try
{
	((bls2::SecretKey*)sec)->set((const bls2::SecretKey *)msk, k, *(const bls2::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeyShare %s\n", e.what());
	return -1;
}

int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n)
	try
{
	((bls2::SecretKey*)sec)->recover((const bls2::SecretKey *)secVec, (const bls2::Id *)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSecretKeyRecover %s\n", e.what());
	return -1;
}

void blsGetPop(blsSignature *sig, const blsSecretKey *sec)
{
	((const bls2::SecretKey*)sec)->getPop(*(bls2::Signature*)sig);
}
int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id)
	try
{
	((bls2::PublicKey*)pub)->set((const bls2::PublicKey*)mpk, k, *(const bls2::Id*)id);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeyShare %s\n", e.what());
	return -1;
}
int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n)
	try
{
	((bls2::PublicKey*)pub)->recover((const bls2::PublicKey*)pubVec, (const bls2::Id*)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsPublicKeyRecover %s\n", e.what());
	return -1;
}
int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, size_t n)
	try
{
	((bls2::Signature*)sig)->recover((const bls2::Signature*)sigVec, (const bls2::Id*)idVec, n);
	return 0;
} catch (std::exception& e) {
	fprintf(stderr, "err blsSignatureRecover %s\n", e.what());
	return -1;
}

int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const char *m, size_t size)
{
	return ((const bls2::Signature*)sig)->verify(*(const bls2::PublicKey*)pub, std::string(m, size));
}

int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub)
{
	return ((const bls2::Signature*)sig)->verify(*(const bls2::PublicKey*)pub);
}

void blsIdSetInt(blsId *id, int x)
{
	mclBnFr_setInt(&id->v, x);
}
size_t blsIdSerialize(void *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_serialize(buf, maxBufSize, &id->v);
}
size_t blsSecretKeySerialize(void *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_serialize(buf, maxBufSize, &sec->v);
}
size_t blsPublicKeySerialize(void *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_serialize(buf, maxBufSize, &pub->v);
}
size_t blsSignatureSerialize(void *buf, size_t maxBufSize, const blsSignature *sig)
{
	return mclBnG1_serialize(buf, maxBufSize, &sig->v);
}
int blsIdDeserialize(blsId *id, const void *buf, size_t bufSize)
{
	return mclBnFr_deserialize(&id->v, buf, bufSize);
}
int blsSecretKeyDeserialize(blsSecretKey *sig, const void *buf, size_t bufSize)
{
	return mclBnFr_deserialize(&sig->v, buf, bufSize);
}
int blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, size_t bufSize)
{
	return mclBnG2_deserialize(&pub->v, buf, bufSize);
}
int blsSignatureDeserialize(blsSignature *sig, const void *buf, size_t bufSize)
{
	return mclBnG1_deserialize(&sig->v, buf, bufSize);
}
int blsIdIsEqual(const blsId *lhs, const blsId *rhs)
{
	return mclBnFr_isEqual(&lhs->v, &rhs->v);
}
int blsSecretKeyIsEqual(const blsSecretKey *lhs, const blsSecretKey *rhs)
{
	return mclBnFr_isEqual(&lhs->v, &rhs->v);
}
int blsPublicKeyIsEqual(const blsPublicKey *lhs, const blsPublicKey *rhs)
{
	return mclBnG2_isEqual(&lhs->v, &rhs->v);
}
int blsSignatureIsEqual(const blsSignature *lhs, const blsSignature *rhs)
{
	return mclBnG1_isEqual(&lhs->v, &rhs->v);
}
void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs)
{
	mclBnFr_add(&sec->v, &sec->v, &rhs->v);
}
void blsSignatureAdd(blsSignature *sig, const blsSignature *rhs)
{
	mclBnG1_add(&sig->v, &sig->v, &rhs->v);
}
void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs)
{
	mclBnG2_add(&pub->v, &pub->v, &rhs->v);
}
int blsIdSetLittleEndian(blsId *id, const void *buf, size_t bufSize)
{
	return mclBnFr_setLittleEndian(&id->v, buf, bufSize);
}
int blsIdSetDecStr(blsId *id, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 10);
}
int blsIdSetHexStr(blsId *id, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 16);
}
size_t blsIdGetLittleEndian(void *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_serialize(buf, maxBufSize, &id->v);
}
size_t blsIdGetDecStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 10);
}
size_t blsIdGetHexStr(char *buf, size_t maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 16);
}
int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, size_t bufSize)
{
	return mclBnFr_setLittleEndian(&sec->v, buf, bufSize);
}
int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 10);
}
int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, size_t bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 16);
}
size_t blsSecretKeyGetLittleEndian(void *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_serialize(buf, maxBufSize, &sec->v);
}
size_t blsSecretKeyGetDecStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 10);
}
size_t blsSecretKeyGetHexStr(char *buf, size_t maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 16);
}
int blsHashToSecretKey(blsSecretKey *sec, const void *buf, size_t bufSize)
{
	return mclBnFr_setHashOf(&sec->v, buf, bufSize);
}
int blsSecretKeySetByCSPRNG(blsSecretKey *sec)
{
	return mclBnFr_setByCSPRNG(&sec->v);
}
int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, size_t bufSize)
{
	return mclBnG2_setStr(&pub->v, buf, bufSize, 16);
}
size_t blsPublicKeyGetHexStr(char *buf, size_t maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_getStr(buf, maxBufSize, &pub->v, 16);
}
int blsSignatureSetHexStr(blsSignature *sig, const char *buf, size_t bufSize)
{
	return mclBnG1_setStr(&sig->v, buf, bufSize, 16);
}
size_t blsSignatureGetHexStr(char *buf, size_t maxBufSize, const blsSignature *sig)
{
	return mclBnG1_getStr(buf, maxBufSize, &sig->v, 16);
}

