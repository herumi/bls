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

} // bls::impl

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
	void setStr(const std::string& str);
	void getStr(std::string& str) const;
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
	void setStr(const std::string& str);
	void getStr(std::string& str) const;
	bool operator==(const PublicKey& rhs) const;
	bool operator!=(const PublicKey& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const PublicKey& pub);
	friend std::istream& operator>>(std::istream& is, PublicKey& pub);
	bool verify(const Sign& sign, const std::string& m) const;
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
	void setStr(const std::string& str);
	void getStr(std::string& str) const;
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
	*/
	void share(std::vector<PrivateKey>& prvVec, int n, int k);
	/*
		recover privateKey from k prvVec
	*/
	void recover(const std::vector<PrivateKey>& prvVec);
};

} // bls
