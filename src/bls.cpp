/**
	@file
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <bls.hpp>
#include <mcl/bn.hpp>
#include <cybozu/crypto.hpp>
#include <cybozu/random_generator.hpp>
#include <vector>
#include <string>

typedef mcl::FpT<mcl::FpTag, 256> Fp;
typedef mcl::bn::BNT<Fp> BN;
typedef BN::Fp2 Fp2;
typedef BN::Fp6 Fp6;
typedef BN::Fp12 Fp12;
typedef BN::G1 G1;
typedef BN::G2 G2;

struct FrTag;
typedef mcl::FpT<FrTag, 256> Fr;
typedef std::vector<Fr> FrVec;

#define PUT(x) std::cout << #x << "=" << x << std::endl;

static cybozu::RandomGenerator& getRG()
{
	static cybozu::RandomGenerator rg;
	return rg;
}

namespace bls {

void init()
{
	BN::init(mcl::bn::CurveFp254BNb);
	G1::setCompressedExpression();
	G2::setCompressedExpression();
	Fr::init(BN::param.r);
//	mcl::setIoMode(mcl::IoHeximal);
}

static const G2& getQ()
{
	static const G2 Q(
		Fp2("12723517038133731887338407189719511622662176727675373276651903807414909099441", "4168783608814932154536427934509895782246573715297911553964171371032945126671"),
		Fp2("13891744915211034074451795021214165905772212241412891944830863846330766296736", "7937318970632701341203597196594272556916396164729705624521405069090520231616")
	);
	return Q;
}

static void mapToG1(G1& P, const Fp& t)
{
	static mcl::bn::MapTo<Fp> mapTo;
	mapTo.calcG1(P, t);
}

static void HashAndMapToG1(G1& P, const std::string& m)
{
	std::string digest = cybozu::crypto::Hash::digest(cybozu::crypto::Hash::N_SHA256, m);
	Fp t;
	t.setArrayMask(digest.c_str(), digest.size());
	mapToG1(P, t);
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
struct Wrap {
	const std::vector<T> *pv;
	Wrap(const std::vector<T>& v) : pv(&v) {}
	const G& operator[](size_t i) const
	{
		return (*pv)[i].self_->get();
	}
	size_t size() const { return pv->size(); }
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
template<class G, class T>
void LagrangeInterpolation(G& r, const T& vec, const IdVec& S)
{
	/*
		delta_{i,S}(0) = prod_{j != i} S[j] / (S[j] - S[i]) = a / b
		where a = prod S[j], b = S[i] * prod_{j != i} (S[j] - S[i])
	*/
	const size_t k = S.size();
	if (vec.size() != k) throw cybozu::Exception("bls:LagrangeInterpolation:bad size") << vec.size() << k;
	if (k < 2) throw cybozu::Exception("bls:LagrangeInterpolation:too small size") << k;
	FrVec delta(k);
	Fr a = S[0].self_->v;
	for (size_t i = 1; i < k; i++) {
		a *= S[i].self_->v;
	}
	for (size_t i = 0; i < k; i++) {
		Fr b = S[i].self_->v;
		for (size_t j = 0; j < k; j++) {
			if (j != i) {
				Fr v = S[j].self_->v - S[i].self_->v;
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
		G::mul(t, vec[i].self_->get(), delta[i]);
		r += t;
	}
}

Id::Id(unsigned int id)
	: self_(new impl::Id())
{
	self_->v = id;
}

Id::~Id()
{
	delete self_;
}

Id::Id(const Id& rhs)
	: self_(new impl::Id(*rhs.self_))
{
}

Id& Id::operator=(const Id& rhs)
{
	*self_ = *rhs.self_;
	return *this;
}

bool Id::operator==(const Id& rhs) const
{
	return self_->v == rhs.self_->v;
}

std::ostream& operator<<(std::ostream& os, const Id& id)
{
	return os << id.self_->v;
}

std::istream& operator>>(std::istream& is, Id& id)
{
	return is >> id.self_->v;
}

bool Id::isZero() const
{
	return self_->v.isZero();
}

void Id::set(const uint64_t *p)
{
	self_->v.setArray(p, keySize);
}

Sign::Sign()
	: self_(new impl::Sign())
{
}

Sign::~Sign()
{
	delete self_;
}

Sign::Sign(const Sign& rhs)
	: self_(new impl::Sign(*rhs.self_))
{
}

Sign& Sign::operator=(const Sign& rhs)
{
	*self_ = *rhs.self_;
	return *this;
}

bool Sign::operator==(const Sign& rhs) const
{
	return self_->sHm == rhs.self_->sHm;
}

std::ostream& operator<<(std::ostream& os, const Sign& s)
{
	return os << s.self_->sHm;
}

std::istream& operator>>(std::istream& os, Sign& s)
{
	return os >> s.self_->sHm;
}

bool Sign::verify(const PublicKey& pub, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m); // Hm = Hash(m)
	Fp12 e1, e2;
	BN::pairing(e1, getQ(), self_->sHm); // e(Q, s Hm)
	BN::pairing(e2, pub.self_->sQ, Hm); // e(sQ, Hm)
	return e1 == e2;
}

bool Sign::verify(const PublicKey& pub) const
{
	std::string str;
	pub.self_->getStr(str);
	return verify(pub, str);
}

void Sign::recover(const SignVec& signVec, const IdVec& idVec)
{
	LagrangeInterpolation(self_->sHm, signVec, idVec);
}

void Sign::add(const Sign& rhs)
{
	self_->sHm += rhs.self_->sHm;
}

PublicKey::PublicKey()
	: self_(new impl::PublicKey())
{
}

PublicKey::~PublicKey()
{
	delete self_;
}

PublicKey::PublicKey(const PublicKey& rhs)
	: self_(new impl::PublicKey(*rhs.self_))
{
}

PublicKey& PublicKey::operator=(const PublicKey& rhs)
{
	*self_ = *rhs.self_;
	return *this;
}

bool PublicKey::operator==(const PublicKey& rhs) const
{
	return self_->sQ == rhs.self_->sQ;
}

std::ostream& operator<<(std::ostream& os, const PublicKey& pub)
{
	return os << pub.self_->sQ;
}

std::istream& operator>>(std::istream& is, PublicKey& pub)
{
	return is >> pub.self_->sQ;
}

void PublicKey::set(const PublicKeyVec& mpk, const Id& id)
{
	Wrap<PublicKey, G2> w(mpk);
	evalPoly(self_->sQ,id.self_->v, w);
}

void PublicKey::recover(const PublicKeyVec& pubVec, const IdVec& idVec)
{
	LagrangeInterpolation(self_->sQ, pubVec, idVec);
}

void PublicKey::add(const PublicKey& rhs)
{
	self_->sQ += rhs.self_->sQ;
}

SecretKey::SecretKey()
	: self_(new impl::SecretKey())
{
}

SecretKey::~SecretKey()
{
	delete self_;
}

SecretKey::SecretKey(const SecretKey& rhs)
	: self_(new impl::SecretKey(*rhs.self_))
{
}

SecretKey& SecretKey::operator=(const SecretKey& rhs)
{
	*self_ = *rhs.self_;
	return *this;
}

bool SecretKey::operator==(const SecretKey& rhs) const
{
	return self_->s == rhs.self_->s;
}

std::ostream& operator<<(std::ostream& os, const SecretKey& sec)
{
	return os << sec.self_->s;
}

std::istream& operator>>(std::istream& is, SecretKey& sec)
{
	return is >> sec.self_->s;
}

void SecretKey::init()
{
	self_->s.setRand(getRG());
}

void SecretKey::set(const uint64_t *p)
{
	self_->s.setArray(p, keySize);
}

void SecretKey::getPublicKey(PublicKey& pub) const
{
	G2::mul(pub.self_->sQ, getQ(), self_->s);
}

void SecretKey::sign(Sign& sign, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m);
	G1::mul(sign.self_->sHm, Hm, self_->s);
}

void SecretKey::getPop(Sign& pop) const
{
	PublicKey pub;
	getPublicKey(pub);
	std::string m;
	pub.self_->getStr(m);
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

void SecretKey::set(const SecretKeyVec& msk, const Id& id)
{
	Wrap<SecretKey, Fr> w(msk);
	evalPoly(self_->s, id.self_->v, w);
}

void SecretKey::recover(const SecretKeyVec& secVec, const IdVec& idVec)
{
	LagrangeInterpolation(self_->s, secVec, idVec);
}

void SecretKey::add(const SecretKey& rhs)
{
	self_->s += rhs.self_->s;
}

} // bls
