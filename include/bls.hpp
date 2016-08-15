#pragma once
/**
	@file
	@brief BLS threshold signature on BN curve
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <vector>
#include <string>
#include <iosfwd>

namespace bls {

namespace impl {

struct PublicKey;
struct PrivateKey;
struct Sign;
struct MasterPublicKey;

} // bls::impl

/*
	e : G2 x G1 -> Fp12
	Q in G2 ; fixed global parameter
	H : {str} -> G1
	s : private key
	sQ ; public key
	s H(m) ; signature of m
	verify ; e(sQ, H(m)) = e(Q, s H(m))
*/
void init();

class Sign {
	impl::Sign *self_;
	int id_;
	friend class PublicKey;
	friend class PrivateKey;
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
public:
	Sign();
	~Sign();
	Sign(const Sign& rhs);
	Sign& operator=(const Sign& rhs);
	bool operator==(const Sign& rhs) const;
	bool operator!=(const Sign& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const Sign& s);
	friend std::istream& operator>>(std::istream& is, Sign& s);

	/*
		recover sign from k signVec
	*/
	void recover(const std::vector<Sign>& signVec);
};

/*
	(Q, sQ, c_1 Q, ..., c_{k-1}Q)
	s = c_0 ; private key
	c_1, ..., c_{k-1} ; secret sharing
	f(x) = c_0 + c_1 x + ... + c_{k-1} x^{k-1}
	f(id) ; private key for user id(>0)
*/
class MasterPublicKey {
	impl::MasterPublicKey *self_;
	friend class PrivateKey;
	friend class PublicKey;
public:
	MasterPublicKey();
	~MasterPublicKey();
	MasterPublicKey(const MasterPublicKey& rhs);
	MasterPublicKey& operator=(const MasterPublicKey& rhs);
	bool operator==(const MasterPublicKey& rhs) const;
	bool operator!=(const MasterPublicKey& rhs) const { return !(*this == rhs); }
	friend std::ostream& operator<<(std::ostream& os, const MasterPublicKey& mpk);
	friend std::istream& operator>>(std::istream& is, MasterPublicKey& mpk);
};

/*
	sQ ; public key
*/
class PublicKey {
	impl::PublicKey *self_;
	int id_;
	friend class PrivateKey;
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
public:
	PublicKey();
	~PublicKey();
	PublicKey(const PublicKey& rhs);
	PublicKey& operator=(const PublicKey& rhs);
	bool operator==(const PublicKey& rhs) const;
	bool operator!=(const PublicKey& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const PublicKey& pub);
	friend std::istream& operator>>(std::istream& is, PublicKey& pub);
	bool verify(const Sign& sign, const std::string& m) const;
	/*
		recover publicKey from k pubVec
	*/
	void recover(const std::vector<PublicKey>& pubVec);
	/*
		validate self by MasterPublicKey
	*/
	bool isValid(const MasterPublicKey& mpk) const;
};

class PrivateKey {
	impl::PrivateKey *self_;
	int id_; // master if id_ = 0, shared if id_ > 0
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
public:
	PrivateKey();
	~PrivateKey();
	PrivateKey(const PrivateKey& rhs);
	PrivateKey& operator=(const PrivateKey& rhs);
	bool operator==(const PrivateKey& rhs) const;
	bool operator!=(const PrivateKey& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const PrivateKey& prv);
	friend std::istream& operator>>(std::istream& is, PrivateKey& prv);
	void init();
	void getPublicKey(PublicKey& pub) const;
	void sign(Sign& sign, const std::string& m) const;
	/*
		k-out-of-n secret sharing of privateKey
		set verifier if mpk is not 0
	*/
	void share(std::vector<PrivateKey>& prvVec, int n, int k, MasterPublicKey *mpk = 0);
	/*
		recover privateKey from k prvVec
	*/
	void recover(const std::vector<PrivateKey>& prvVec);
};

} //bls
