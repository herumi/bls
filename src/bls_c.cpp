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
/*
	BLS signature
	e : G1 x G2 -> Fp12
	Q in G2 ; fixed global parameter
	H : {str} -> G1
	s : secret key
	sQ ; public key
	s H(m) ; signature of m
	verify ; e(sQ, H(m)) = e(Q, s H(m))
*/

static G2 g_Q;
static std::vector<Fp6> g_Qcoeff; // precomputed Q
static const G2& getQ() { return g_Q; }
static const std::vector<Fp6>& getQcoeff() { return g_Qcoeff; }

int blsInit(int curve, int maxUnitSize)
	try
{
	if (mclBn_init(curve, maxUnitSize) != 0) return -1;
	BN::mapToG2(g_Q, 1);
	BN::precomputeG2(g_Qcoeff, getQ());
	return 0;
} catch (std::exception&) {
	return -1;
}

static inline Fr *cast(blsId* x) { return (Fr *)x; }
static inline Fr *cast(blsSecretKey* x) { return (Fr *)x; }
static inline G1 *cast(blsSignature* x) { return (G1 *)x; }
static inline G2 *cast(blsPublicKey* x) { return (G2 *)x; }
static inline const Fr *cast(const blsId* x) { return (const Fr *)x; }
static inline const Fr *cast(const blsSecretKey* x) { return (const Fr *)x; }
static inline const G1 *cast(const blsSignature* x) { return (const G1 *)x; }
static inline const G2 *cast(const blsPublicKey* x) { return (const G2 *)x; }

static inline const mclBnG1 *cast(const G1* x) { return (const mclBnG1*)x; }
static inline const mclBnG2 *cast(const G2* x) { return (const mclBnG2*)x; }
/*
	recover out = f(0) by { (x, y) | x = S[i], y = f(x) = vec[i] }
*/
template<class G, class F>
int LagrangeInterpolation(G& out, const F *S, const G *vec, size_t k)
{
	/*
		delta_{i,S}(0) = prod_{j != i} S[j] / (S[j] - S[i]) = a / b
		where a = prod S[j], b = S[i] * prod_{j != i} (S[j] - S[i])
	*/
	if (k < 2) return -1;
	std::vector<F> delta(k);
	F a = S[0];
	for (size_t i = 1; i < k; i++) {
		a *= S[i];
	}
	if (a.isZero()) return -1;
	for (size_t i = 0; i < k; i++) {
		F b = S[i];
		for (size_t j = 0; j < k; j++) {
			if (j != i) {
				F v = S[j] - S[i];
				if (v.isZero()) return -1;
				b *= v;
			}
		}
		delta[i] = a / b;
	}

	/*
		f(0) = sum_i f(S[i]) delta_{i,S}(0)
	*/
	G r, t;
	r.clear();
	for (size_t i = 0; i < delta.size(); i++) {
		G::mul(t, vec[i], delta[i]);
		r += t;
	}
	out = r;
	return 0;
}

/*
	out = f(x) = c[0] + c[1] * x + c[2] * x^2 + ... + c[cSize - 1] * x^(cSize - 1)
*/
template<class G, class T>
int evalPoly(G& out, const G *c, size_t cSize, const T& x)
{
	if (cSize < 2) return -1;
	G y = c[cSize - 1];
	for (int i = (int)cSize - 2; i >= 0; i--) {
		G::mul(y, y, x);
		G::add(y, y, c[i]);
	}
	out = y;
	return 0;
}

/*
	e(P1, Q1) == e(P2, Q2)
	<=> finalExp(ML(P1, Q1)) == finalExp(ML(P2, Q2))
	<=> finalExp(ML(P1, Q1) / ML(P2, Q2)) == 1
	<=> finalExp(ML(P1, Q1) * ML(-P2, Q2)) == 1
	Q1 is precomputed
*/
bool isEqualTwoPairings(const G1& P1, const Fp6* Q1coeff, const G1& P2, const G2& Q2)
{
	std::vector<Fp6> Q2coeff;
	BN::precomputeG2(Q2coeff, Q2);
	Fp12 e;
	BN::precomputedMillerLoop2(e, P1, Q1coeff, -P2, Q2coeff.data());
	BN::finalExp(e, e);
	return e.isOne();
}

int mclBn_FrLagrangeInterpolation(mclBnFr *out, const mclBnFr *xVec, const mclBnFr *yVec, size_t k)
{
	return LagrangeInterpolation(*cast(out), cast(xVec), cast(yVec), k);
}
int mclBn_G1LagrangeInterpolation(mclBnG1 *out, const mclBnFr *xVec, const mclBnG1 *yVec, size_t k)
{
	return LagrangeInterpolation(*cast(out), cast(xVec), cast(yVec), k);
}
int mclBn_G2LagrangeInterpolation(mclBnG2 *out, const mclBnFr *xVec, const mclBnG2 *yVec, size_t k)
{
	return LagrangeInterpolation(*cast(out), cast(xVec), cast(yVec), k);
}
int mclBn_FrEvaluatePolynomial(mclBnFr *out, const mclBnFr *cVec, size_t cSize, const mclBnFr *x)
{
	return evalPoly(*cast(out), cast(cVec), cSize, *cast(x));
}
int mclBn_G1EvaluatePolynomial(mclBnG1 *out, const mclBnG1 *cVec, size_t cSize, const mclBnFr *x)
{
	return evalPoly(*cast(out), cast(cVec), cSize, *cast(x));
}
int mclBn_G2EvaluatePolynomial(mclBnG2 *out, const mclBnG2 *cVec, size_t cSize, const mclBnFr *x)
{
	return evalPoly(*cast(out), cast(cVec), cSize, *cast(x));
}

size_t checkAndCopy(char *buf, size_t maxBufSize, const std::string& s)
{
	if (s.size() > maxBufSize + 1) {
		return 0;
	}
	memcpy(buf, s.c_str(), s.size());
	buf[s.size()] = '\0';
	return s.size();
}

size_t blsGetOpUnitSize() // FpUint64Size
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

void blsGetGeneratorOfG2(blsPublicKey *pub)
{
	*(G2*)pub = getQ();
}

void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec)
{
	mclBnG2_mul(&pub->v, cast(&getQ()), &sec->v);
}
void blsSign(blsSignature *sig, const blsSecretKey *sec, const void *m, size_t size)
{
	G1 Hm;
	BN::hashAndMapToG1(Hm, m, size);
	mclBnG1_mulCT(&sig->v, cast(&Hm), &sec->v);
}
int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, size_t k, const blsId *id)
{
	return mclBn_FrEvaluatePolynomial(&sec->v, &msk->v, k, &id->v);
}

int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, size_t n)
{
	return mclBn_FrLagrangeInterpolation(&sec->v, &idVec->v, &secVec->v, n);
}

void blsGetPop(blsSignature *sig, const blsSecretKey *sec)
{
	blsPublicKey pub;
	blsGetPublicKey(&pub, sec);
	char buf[1024];
	size_t n = mclBnG2_serialize(buf, sizeof(buf), &pub.v);
	assert(n);
	blsSign(sig, sec, buf, n);
}
int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, size_t k, const blsId *id)
{
	return mclBn_G2EvaluatePolynomial(&pub->v, &mpk->v, k, &id->v);
}
int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, size_t n)
{
	return mclBn_G2LagrangeInterpolation(&pub->v, &idVec->v, &pubVec->v, n);
}
int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, size_t n)
{
	return mclBn_G1LagrangeInterpolation(&sig->v, &idVec->v, &sigVec->v, n);
}

int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const void *m, size_t size)
{
	G1 Hm;
	BN::hashAndMapToG1(Hm, m, size);
	/*
		e(sHm, Q) = e(Hm, sQ)
		e(sig, Q) = e(Hm, pub)
	*/
	return isEqualTwoPairings(*cast(&sig->v), getQcoeff().data(), Hm, *cast(&pub->v));
}

int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub)
{
	char buf[1024];
	size_t n = mclBnG2_serialize(buf, sizeof(buf), &pub->v);
	assert(n);
	return blsVerify(sig, pub, buf, n);
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
void blsDHKeyExchange(blsPublicKey *out, const blsSecretKey *sec, const blsPublicKey *pub)
{
	mclBnG2_mulCT(&out->v, &pub->v, &sec->v);
}

