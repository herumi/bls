#include <bls/bls384_256.h>
#include <stdint.h>
#include <sstream>

#if defined(__GNUC__) && !defined(__EMSCRIPTEN__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
#endif

void init(int curveType) throw(std::exception)
{
	int ret = blsInit(curveType, MCLBN_COMPILED_TIME_VAR);
	if (ret) {
		throw std::runtime_error("bad curveType");
	}
}

class SecretKey;
class PublicKey;
class Signature;

class SecretKey {
	blsSecretKey self_;
public:
	SecretKey() {}
	SecretKey(const SecretKey& rhs) : self_(rhs.self_) {}
	SecretKey(int x)
    {
        setInt(x);
    }
	bool equals(const SecretKey& rhs) const
	{
		return blsSecretKeyIsEqual(&self_, &rhs.self_) != 0;
	}
	bool isZero() const { return blsSecretKeyIsZero(&self_) != 0; }
	void setStr(const std::string& str, int base = 10) throw(std::exception)
	{
		size_t n = 0;
		const size_t len = str.size();
		if (base == 10) {
			n = blsSecretKeySetDecStr(&self_, str.c_str(), len);
		} else if (base == 16) {
			n = blsSecretKeySetHexStr(&self_, str.c_str(), len);
		}
		if (n == 0 || n != len) throw std::runtime_error("bad str");
	}
	void setInt(int x)
	{
        blsIdSetInt((blsId*)&self_, x);
	}
	void clear()
	{
        memset(&self_, 0, sizeof(self_));
	}
	void setByCSPRNG()
	{
        blsSecretKeySetByCSPRNG(&self_);
	}
	std::string toString(int base = 10) const throw(std::exception)
	{
		size_t n = 0;
		std::string s;
		s.resize(128);
		if (base == 10) {
			n = blsSecretKeyGetDecStr(&s[0], s.size(), &self_);
		} else if (base == 16) {
			n = blsSecretKeyGetHexStr(&s[0], s.size(), &self_);
		}
		if (n == 0) throw std::runtime_error("err toString");
		s.resize(n);
		return s;
	}
	void deserialize(const char *cbuf, size_t bufSize) throw(std::exception)
	{
        int n = blsSecretKeyDeserialize(&self_, cbuf, bufSize);
        if (n == 0) {
            throw std::runtime_error("blsSecretKeyDeserialize");
        }
	}
	void serialize(std::string& out) const throw(std::exception)
	{
        out.resize(128);
        size_t n = blsSecretKeySerialize(&out[0], out.size(), &self_);
        if (n == 0) {
            throw std::runtime_error("blsSecretKeySerialize");
        }
        out.resize(n);
	}
};

#if defined(__GNUC__) && !defined(__EMSCRIPTEN__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
