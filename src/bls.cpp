/**
	@file
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <cybozu/crypto.hpp>
#include <cybozu/random_generator.hpp>
#include <vector>
#include <string>
#include <bls.hpp>
#if BLS_MAX_OP_UNIT_SIZE == 4
#include <mcl/bn256.hpp>
using namespace mcl::bn256;
#elif BLS_MAX_OP_UNIT_SIZE == 6
#include <mcl/bn384.hpp>
using namespace mcl::bn384;
#else
	#error "define BLS_MAX_OP_UNIT_SIZE 4(or 6)"
#endif

typedef std::vector<Fr> FrVec;

#define PUT(x) std::cout << #x << "=" << x << std::endl;

static cybozu::RandomGenerator& getRG()
{
	static cybozu::RandomGenerator rg;
	return rg;
}

const std::vector<Fp6> *g_pQcoeff;
const G2 *g_pQ;

namespace bls {

static const G2& getQ() { return *g_pQ; }
static const std::vector<Fp6>& getQcoeff() { return *g_pQcoeff; }

static void HashAndMapToG1(G1& P, const std::string& m)
{
	Fp t;
	t.setMsg(m);
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

struct Sign {
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

void init(int curve, int maxUnitSize)
{
	if (maxUnitSize != BLS_MAX_OP_UNIT_SIZE) throw cybozu::Exception("bls:init:bad maxUnitSize") << maxUnitSize << BLS_MAX_OP_UNIT_SIZE;
	mcl::bn::CurveParam cp;
	switch (curve) {
	case bls::CurveFp254BNb:
		cp = mcl::bn::CurveFp254BNb;
		break;
#if BLS_MAX_OP_UNIT_SIZE == 6
	case bls::CurveFp382_1:
		cp = mcl::bn::CurveFp382_1;
		break;
	case bls::CurveFp382_2:
		cp = mcl::bn::CurveFp382_2;
		break;
#endif
	default:
		throw cybozu::Exception("bls:init:bad curve") << curve;
	}
	BN::init(cp);
	G1::setCompressedExpression();
	G2::setCompressedExpression();
	Fr::init(BN::param.r);
//	mcl::setIoMode(mcl::IoHeximal);
	assert(sizeof(Id) == sizeof(impl::Id));
	assert(sizeof(SecretKey) == sizeof(impl::SecretKey));
	assert(sizeof(PublicKey) == sizeof(impl::PublicKey));
	assert(sizeof(Sign) == sizeof(impl::Sign));
	static G2 Q;
	if (curve == bls::CurveFp254BNb) {
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
}
size_t getOpUnitSize()
{
	return Fp::getUnitSize() * sizeof(mcl::fp::Unit) / sizeof(uint64_t);
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

bool Id::isZero() const
{
	return getInner().v.isZero();
}

void Id::set(const uint64_t *p)
{
	getInner().v.setArrayMask(p, keySize);
}

bool Sign::operator==(const Sign& rhs) const
{
	return getInner().sHm == rhs.getInner().sHm;
}

std::ostream& operator<<(std::ostream& os, const Sign& s)
{
	return writeAsHex(os, s.getInner().sHm);
}

std::istream& operator>>(std::istream& os, Sign& s)
{
	return os >> s.getInner().sHm;
}

bool Sign::verify(const PublicKey& pub, const std::string& m) const
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

bool Sign::verify(const PublicKey& pub) const
{
	std::string str;
	pub.getInner().sQ.getStr(str);
	return verify(pub, str);
}

void Sign::recover(const SignVec& signVec, const IdVec& idVec)
{
	if (signVec.size() != idVec.size()) throw cybozu::Exception("Sign:recover:bad size") << signVec.size() << idVec.size();
	recover(signVec.data(), idVec.data(), signVec.size());
}

void Sign::recover(const Sign* signVec, const Id *idVec, size_t n)
{
	WrapArray<Sign, G1> signW(signVec, n);
	WrapArray<Id, Fr> idW(idVec, n);
	LagrangeInterpolation(getInner().sHm, signW, idW);
}

void Sign::add(const Sign& rhs)
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

void SecretKey::init()
{
	getInner().s.setRand(getRG());
}

void SecretKey::set(const uint64_t *p)
{
	getInner().s.setArrayMask(p, keySize);
}

void SecretKey::getPublicKey(PublicKey& pub) const
{
	G2::mul(pub.getInner().sQ, getQ(), getInner().s);
}

void SecretKey::sign(Sign& sign, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m);
	G1::mul(sign.getInner().sHm, Hm, getInner().s);
}
// constant time sign
void SecretKey::signCT(Sign& sign, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m);
	G1::mulCT(sign.getInner().sHm, Hm, getInner().s);
}

void SecretKey::getPop(Sign& pop) const
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

} // bls
