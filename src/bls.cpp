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
	G2::setCompressedExpression();
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
	bool verify(const PublicKey& pub, const std::string& m) const;
};

struct PublicKey {
	G2 sQ;
	void init(const Fr& s)
	{
		G2::mul(sQ, getQ(), s);
	}
	const G2& get() const { return sQ; }
};

inline bool Sign::verify(const PublicKey& pub, const std::string& m) const
{
	G1 Hm;
	HashAndMapToG1(Hm, m); // Hm = Hash(m)
	Fp12 e1, e2;
	BN::pairing(e1, getQ(), sHm); // e(Q, s Hm)
	BN::pairing(e2, pub.sQ, Hm); // e(sQ, Hm)
	return e1 == e2;
}

struct SecretKey {
	Fr s;
	const Fr& get() const { return s; }
	void init(const uint64_t *p)
	{
		if (p) {
			s.setArray(p, keySize);
		} else {
			s.setRand(getRG());
		}
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

bool Sign::verify(const PublicKey& pub, const std::string& m) const
{
	return self_->verify(*pub.self_, m);
}
bool Sign::verify(const PublicKey& pub) const
{
	std::string str;
	pub.getStr(str);
	return verify(pub, str);
}
void Sign::recover(const SignVec& signVec)
{
	G1 sHm;
	LagrangeInterpolation(sHm, signVec);
	self_->sHm = sHm;
	id_ = 0;
}

void Sign::add(const Sign& rhs)
{
	if (id_ != 0 || rhs.id_ != 0) throw cybozu::Exception("bls:Sign:add:bad id") << id_ << rhs.id_;
	self_->sHm += rhs.self_->sHm;
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

void PublicKey::getStr(std::string& str) const
{
	std::ostringstream os;
	os << *this;
	str = os.str();
}

void PublicKey::set(const PublicKeyVec& mpk, int id)
{
	Wrap<PublicKey, G2> w(mpk);
	evalPoly(self_->sQ, Fr(id), w);
	id_ = id;
}

void PublicKey::recover(const PublicKeyVec& pubVec)
{
	G2 sQ;
	LagrangeInterpolation(sQ, pubVec);
	self_->sQ = sQ;
	id_ = 0;
}

void PublicKey::add(const PublicKey& rhs)
{
	if (id_ != 0 || rhs.id_ != 0) throw cybozu::Exception("bls:PublicKey:add:bad id") << id_ << rhs.id_;
	self_->sQ += rhs.self_->sQ;
}

SecretKey::SecretKey()
	: self_(new impl::SecretKey())
	, id_(0)
{
}

SecretKey::~SecretKey()
{
	delete self_;
}

SecretKey::SecretKey(const SecretKey& rhs)
	: self_(new impl::SecretKey(*rhs.self_))
	, id_(rhs.id_)
{
}

SecretKey& SecretKey::operator=(const SecretKey& rhs)
{
	*self_ = *rhs.self_;
	id_ = rhs.id_;
	return *this;
}

bool SecretKey::operator==(const SecretKey& rhs) const
{
	return id_ == rhs.id_ && self_->s == rhs.self_->s;
}

std::ostream& operator<<(std::ostream& os, const SecretKey& sec)
{
	return os << sec.id_ << ' ' << sec.self_->s;
}

std::istream& operator>>(std::istream& is, SecretKey& sec)
{
	return is >> sec.id_ >> sec.self_->s;
}

void SecretKey::init(const uint64_t *p)
{
	self_->init(p);
}

void SecretKey::getPublicKey(PublicKey& pub) const
{
	self_->getPublicKey(*pub.self_);
	pub.id_ = id_;
}

void SecretKey::sign(Sign& sign, const std::string& m) const
{
	self_->sign(*sign.self_, m);
	sign.id_ = id_;
}

void SecretKey::getPop(Sign& pop, const PublicKey& pub) const
{
	std::string m;
	pub.getStr(m);
	sign(pop, m);
}

void SecretKey::getMasterSecretKey(SecretKeyVec& msk, int k) const
{
	if (k <= 1) throw cybozu::Exception("bls:SecretKey:getMasterSecretKey:bad k") << k;
	msk.resize(k);
	msk[0] = *this;
	for (int i = 1; i < k; i++) {
		msk[i].init();
	}
}

void SecretKey::set(const SecretKeyVec& msk, int id)
{
	Wrap<SecretKey, Fr> w(msk);
	evalPoly(self_->s, id, w);
	id_ = id;
}

void SecretKey::recover(const SecretKeyVec& secVec)
{
	Fr s;
	LagrangeInterpolation(s, secVec);
	self_->s = s;
	id_ = 0;
}

void SecretKey::add(const SecretKey& rhs)
{
	if (id_ != 0 || rhs.id_ != 0) throw cybozu::Exception("bls:SecretKey:add:bad id") << id_ << rhs.id_;
	self_->s += rhs.self_->s;
}

void getMasterPublicKey(PublicKeyVec& mpk, const SecretKeyVec& msk)
{
	mpk.resize(msk.size());
	for (size_t i = 0; i < msk.size(); i++) {
		msk[i].getPublicKey(mpk[i]);
	}
}

void getPopVec(SignVec& popVec, const SecretKeyVec& msk, const PublicKeyVec& mpk)
{
	if (msk.size() != mpk.size()) throw cybozu::Exception("bls:getPopVec:bad size") << msk.size() << mpk.size();
	const size_t n = msk.size();
	popVec.resize(n);
	std::string m;
	for (size_t i = 0; i < n; i++) {
		mpk[i].getStr(m);
		msk[i].sign(popVec[i], m);
	}
}

} // bls
