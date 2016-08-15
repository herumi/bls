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
typedef std::vector<int> IntVec;

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
//	G2::setCompressedExpression();
	Fr::init(BN::param.r);
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

template<class T, class G>
void evalPoly(G& y, const T& x, const std::vector<G>& c)
{
	if (c.size() < 2) throw cybozu::Exception("bls:evalPoly:bad size") << c.size();
	y = c[c.size() - 1];
	for (int i = (int)c.size() - 2; i >= 0; i--) {
		G::mul(y, y, x);
		G::add(y, y, c[i]);
	}
}

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
	void eval(Fr& y, int id) const
	{
		if (id == 0) throw cybozu::Exception("bls:Polynomial:eval:id is zero");
		evalPoly(y, Fr(id), c);
	}
};

/*
	delta_{i,S}(0) = prod_{j != i} S[j] / (S[j] - S[i]) = a / b
	where a = prod S[j], b = S[i] * prod_{j != i} (S[j] - S[i])
*/
static void calcDelta(FrVec& delta, const IntVec& S)
{
	const size_t k = S.size();
	if (k < 2) throw cybozu::Exception("bls:calcDelta:bad size") << k;
	delta.resize(k);
	Fr a = S[0];
	for (size_t i = 1; i < k; i++) {
		a *= S[i];
	}
	for (size_t i = 0; i < k; i++) {
		Fr b = S[i];
		for (size_t j = 0; j < k; j++) {
			if (j != i) {
				int v = S[j] - S[i];
				if (v == 0) throw cybozu::Exception("bls:calcDelta:S has same id") << i << j;
				b *= v;
			}
		}
		delta[i] = a / b;
	}
}

template<class G, class T>
void LagrangeInterpolation(G& r, const T& vec)
{
	IntVec S(vec.size());
	for (size_t i = 0; i < vec.size(); i++) {
		S[i] = vec[i].getId();
	}
	FrVec delta;
	calcDelta(delta, S);

	r.clear();
	G t;
	for (size_t i = 0; i < delta.size(); i++) {
		G::mul(t, vec[i].self_->get(), delta[i]);
		r += t;
	}
}

namespace impl {

struct Sign {
	G1 sHm; // s Hash(m)
	const G1& get() const { return sHm; }
};

struct PublicKey {
	G2 sQ;
	void init(const Fr& s)
	{
		G2::mul(sQ, getQ(), s);
	}
	bool verify(const Sign& sign, const std::string& m) const
	{
		G1 Hm;
		HashAndMapToG1(Hm, m); // Hm = Hash(m)
		Fp12 e1, e2;
		BN::pairing(e1, getQ(), sign.sHm); // e(Q, s Hm)
		BN::pairing(e2, sQ, Hm); // e(sQ, Hm)
		return e1 == e2;
	}
	const G2& get() const { return sQ; }
};

struct Verifier {
	std::vector<G2> vecR;
};

struct PrivateKey {
	Fr s;
	const Fr& get() const { return s; }
	void init()
	{
		s.setRand(getRG());
	}
	void getPublicKey(PublicKey& pub) const
	{
		pub.init(s);
	}
	void sign(Sign& sign, const std::string& m) const
	{
		G1 Hm;
		HashAndMapToG1(Hm, m);
		G1::mul(sign.sHm, Hm, s);
	}
};

} // mcl::bls::impl

Sign::Sign()
	: self_(new impl::Sign())
	, id_(0)
{
}

Sign::~Sign()
{
	delete self_;
}

Sign::Sign(const Sign& rhs)
	: self_(new impl::Sign(*rhs.self_))
	, id_(rhs.id_)
{
}

Sign& Sign::operator=(const Sign& rhs)
{
	*self_ = *rhs.self_;
	id_ = rhs.id_;
	return *this;
}

bool Sign::operator==(const Sign& rhs) const
{
	return id_ == rhs.id_ && self_->sHm == rhs.self_->sHm;
}

std::ostream& operator<<(std::ostream& os, const Sign& s)
{
	return os << s.id_ << ' ' << s.self_->sHm;
}

std::istream& operator>>(std::istream& os, Sign& s)
{
	return os >> s.id_ >> s.self_->sHm;
}

void Sign::recover(const std::vector<Sign>& signVec)
{
	G1 sHm;
	LagrangeInterpolation(sHm, signVec);
	self_->sHm = sHm;
	id_ = 0;
}

Verifier::Verifier()
	: self_(new impl::Verifier())
{
}

Verifier::~Verifier()
{
	delete self_;
}

Verifier::Verifier(const Verifier& rhs)
	: self_(new impl::Verifier(*rhs.self_))
{
}

Verifier& Verifier::operator=(const Verifier& rhs)
{
	*self_ = *rhs.self_;
	return *this;
}

bool Verifier::operator==(const Verifier& rhs) const
{
	return self_->vecR == rhs.self_->vecR;
}

std::ostream& operator<<(std::ostream& os, const Verifier& ver)
{
	const size_t n = ver.self_->vecR.size();
	os << n;
	for (size_t i = 0; i < n; i++) {
		os << '\n' << ver.self_->vecR[i];
	}
	return os;
}

std::istream& operator>>(std::istream& is, Verifier& ver)
{
	size_t n;
	is >> n;
	ver.self_->vecR.resize(n);
	for (size_t i = 0; i < n; i++) {
		is >> ver.self_->vecR[i];
	}
	return is;
}

PublicKey::PublicKey()
	: self_(new impl::PublicKey())
	, id_(0)
{
}

PublicKey::~PublicKey()
{
	delete self_;
}

PublicKey::PublicKey(const PublicKey& rhs)
	: self_(new impl::PublicKey(*rhs.self_))
	, id_(rhs.id_)
{
}

PublicKey& PublicKey::operator=(const PublicKey& rhs)
{
	*self_ = *rhs.self_;
	id_ = rhs.id_;
	return *this;
}

bool PublicKey::operator==(const PublicKey& rhs) const
{
	return id_ == rhs.id_ && self_->sQ == rhs.self_->sQ;
}

std::ostream& operator<<(std::ostream& os, const PublicKey& pub)
{
	return os << pub.id_ << ' ' << pub.self_->sQ;
}

std::istream& operator>>(std::istream& is, PublicKey& pub)
{
	return is >> pub.id_ >> pub.self_->sQ;
}

bool PublicKey::verify(const Sign& sign, const std::string& m) const
{
	return self_->verify(*sign.self_, m);
}

void PublicKey::recover(const std::vector<PublicKey>& pubVec)
{
	G2 sQ;
	LagrangeInterpolation(sQ, pubVec);
	self_->sQ = sQ;
	id_ = 0;
}

bool PublicKey::isValid(const Verifier& ver) const
{
	G2 v;
	evalPoly(v, Fr(id_), ver.self_->vecR);
	return v == self_->sQ;
}

PrivateKey::PrivateKey()
	: self_(new impl::PrivateKey())
	, id_(0)
{
}

PrivateKey::~PrivateKey()
{
	delete self_;
}

PrivateKey::PrivateKey(const PrivateKey& rhs)
	: self_(new impl::PrivateKey(*rhs.self_))
	, id_(rhs.id_)
{
}

PrivateKey& PrivateKey::operator=(const PrivateKey& rhs)
{
	*self_ = *rhs.self_;
	id_ = rhs.id_;
	return *this;
}

bool PrivateKey::operator==(const PrivateKey& rhs) const
{
	return id_ == rhs.id_ && self_->s == rhs.self_->s;
}

void PrivateKey::init()
{
	self_->init();
}

void PrivateKey::getPublicKey(PublicKey& pub) const
{
	self_->getPublicKey(*pub.self_);
	pub.id_ = id_;
}

std::ostream& operator<<(std::ostream& os, const PrivateKey& prv)
{
	return os << prv.id_ << ' ' << prv.self_->s;
}

std::istream& operator>>(std::istream& is, PrivateKey& prv)
{
	return is >> prv.id_ >> prv.self_->s;
}

void PrivateKey::sign(Sign& sign, const std::string& m) const
{
	self_->sign(*sign.self_, m);
	sign.id_ = id_;
}

void PrivateKey::share(std::vector<PrivateKey>& prvVec, int n, int k, Verifier *ver)
{
	if (id_ != 0) throw cybozu::Exception("bls:PrivateKey:share:already shared") << id_;
	if (n <= 0 || k <= 0 || k > n) throw cybozu::Exception("bls:PrivateKey:share:bad n, k") << n << k;
	Polynomial poly;
	poly.init(self_->s, k);
	prvVec.resize(n);
	for (int i = 0; i < n; i++) {
		int id = i + 1;
		poly.eval(prvVec[i].self_->s, id);
		prvVec[i].id_ = id;
	}
	if (ver == 0) return;
	std::vector<G2>& vecR = ver->self_->vecR;
	vecR.resize(k);
	for (size_t i = 0; i < vecR.size(); i++) {
		G2::mul(vecR[i], getQ(), poly.c[i]);
	}
}

void PrivateKey::recover(const std::vector<PrivateKey>& prvVec)
{
	Fr s;
	LagrangeInterpolation(s, prvVec);
	self_->s = s;
	id_ = 0;
}

} // bls
