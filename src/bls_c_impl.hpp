#define MCLBN_DONT_EXPORT
#define BLS_DLL_EXPORT

#include <bls/bls.h>

#include "../mcl/src/bn_c_impl.hpp"

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
const size_t maxQcoeffN = 128;
static mcl::FixedArray<Fp6, maxQcoeffN> g_Qcoeff; // precomputed Q
inline const G2& getQ() { return g_Q; }
inline const mcl::FixedArray<Fp6, maxQcoeffN>& getQcoeff() { return g_Qcoeff; }

int blsInitNotThreadSafe(int curve, int compiledTimeVar)
{
	int ret = mclBn_init(curve, compiledTimeVar);
	if (ret < 0) return ret;
	bool b;

	if (curve == MCL_BN254) {
		const char *Qx_BN254 = "11ccb44e77ac2c5dc32a6009594dbe331ec85a61290d6bbac8cc7ebb2dceb128 f204a14bbdac4a05be9a25176de827f2e60085668becdd4fc5fa914c9ee0d9a";
		const char *Qy_BN254 = "7c13d8487903ee3c1c5ea327a3a52b6cc74796b1760d5ba20ed802624ed19c8 8f9642bbaacb73d8c89492528f58932f2de9ac3e80c7b0e41f1a84f1c40182";
		g_Q.x.setStr(&b, Qx_BN254, 16);
		g_Q.y.setStr(&b, Qy_BN254, 16);
		g_Q.z = 1;
	} else {
		mapToG2(&b, g_Q, 1);
	}
	if (!b) return -100;
	if (curve == MCL_BN254) {
		#include "./qcoeff-bn254.hpp"
		g_Qcoeff.resize(BN::param.precomputedQcoeffSize);
		assert(g_Qcoeff.size() == CYBOZU_NUM_OF_ARRAY(tbl));
		for (size_t i = 0; i < g_Qcoeff.size(); i++) {
			Fp6& x6 = g_Qcoeff[i];
			for (size_t j = 0; j < 6; j++) {
				Fp& x = x6.getFp0()[j];
				mcl::fp::Unit *p = const_cast<mcl::fp::Unit*>(x.getUnit());
				for (size_t k = 0; k < 4; k++) {
					p[k] = QcoeffTblBN254[i][j][k];
				}
			}
		}
	} else {
		precomputeG2(&b, g_Qcoeff, getQ());
	}
	if (!b) return -101;
	return 0;
}

#ifdef __EMSCRIPTEN__
extern "C" BLS_DLL_API void *blsMalloc(size_t n)
{
	return malloc(n);
}
extern "C" BLS_DLL_API void blsFree(void *p)
{
	free(p);
}
#endif

#if !defined(__EMSCRIPTEN__) && !defined(__wasm__)
	#if defined(CYBOZU_CPP_VERSION) && CYBOZU_CPP_VERSION >= CYBOZU_CPP_VERSION_CPP11
	#include <mutex>
		#define USE_STD_MUTEX
	#else
	#include <cybozu/mutex.hpp>
		#define USE_CYBOZU_MUTEX
	#endif
#endif

int blsInit(int curve, int compiledTimeVar)
{
	int ret = 0;
#ifdef USE_STD_MUTEX
	static std::mutex m;
	std::lock_guard<std::mutex> lock(m);
#elif defined(USE_CYBOZU_MUTEX)
	static cybozu::Mutex m;
	cybozu::AutoLock lock(m);
#endif
	static int g_curve = -1;
	if (g_curve != curve) {
		ret = blsInitNotThreadSafe(curve, compiledTimeVar);
		g_curve = curve;
	}
	return ret;
}

static inline const mclBnG1 *cast(const G1* x) { return (const mclBnG1*)x; }
static inline const mclBnG2 *cast(const G2* x) { return (const mclBnG2*)x; }

void blsIdSetInt(blsId *id, int x)
{
	mclBnFr_setInt(&id->v, x);
}

int blsSecretKeySetLittleEndian(blsSecretKey *sec, const void *buf, mclSize bufSize)
{
	return mclBnFr_setLittleEndian(&sec->v, buf, bufSize);
}

void blsGetPublicKey(blsPublicKey *pub, const blsSecretKey *sec)
{
	mclBnG2_mul(&pub->v, cast(&getQ()), &sec->v);
}

void blsSign(blsSignature *sig, const blsSecretKey *sec, const void *m, mclSize size)
{
	G1 Hm;
	hashAndMapToG1(Hm, m, size);
	mclBnG1_mulCT(&sig->v, cast(&Hm), &sec->v);
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
	Fp12 e;
	precomputedMillerLoop2mixed(e, P2, Q2, -P1, Q1coeff);
	finalExp(e, e);
	return e.isOne();
}

int blsVerify(const blsSignature *sig, const blsPublicKey *pub, const void *m, mclSize size)
{
	G1 Hm;
	hashAndMapToG1(Hm, m, size);
	/*
		e(sHm, Q) = e(Hm, sQ)
		e(sig, Q) = e(Hm, pub)
	*/
	return isEqualTwoPairings(*cast(&sig->v), getQcoeff().data(), Hm, *cast(&pub->v));
}

mclSize blsIdSerialize(void *buf, mclSize maxBufSize, const blsId *id)
{
	return mclBnFr_serialize(buf, maxBufSize, &id->v);
}

mclSize blsSecretKeySerialize(void *buf, mclSize maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_serialize(buf, maxBufSize, &sec->v);
}

mclSize blsPublicKeySerialize(void *buf, mclSize maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_serialize(buf, maxBufSize, &pub->v);
}

mclSize blsSignatureSerialize(void *buf, mclSize maxBufSize, const blsSignature *sig)
{
	return mclBnG1_serialize(buf, maxBufSize, &sig->v);
}

mclSize blsIdDeserialize(blsId *id, const void *buf, mclSize bufSize)
{
	return mclBnFr_deserialize(&id->v, buf, bufSize);
}

mclSize blsSecretKeyDeserialize(blsSecretKey *sig, const void *buf, mclSize bufSize)
{
	return mclBnFr_deserialize(&sig->v, buf, bufSize);
}

mclSize blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, mclSize bufSize)
{
	return mclBnG2_deserialize(&pub->v, buf, bufSize);
}

mclSize blsSignatureDeserialize(blsSignature *sig, const void *buf, mclSize bufSize)
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

int blsSecretKeyShare(blsSecretKey *sec, const blsSecretKey* msk, mclSize k, const blsId *id)
{
	return mclBn_FrEvaluatePolynomial(&sec->v, &msk->v, k, &id->v);
}

int blsPublicKeyShare(blsPublicKey *pub, const blsPublicKey *mpk, mclSize k, const blsId *id)
{
	return mclBn_G2EvaluatePolynomial(&pub->v, &mpk->v, k, &id->v);
}

int blsSecretKeyRecover(blsSecretKey *sec, const blsSecretKey *secVec, const blsId *idVec, mclSize n)
{
	return mclBn_FrLagrangeInterpolation(&sec->v, &idVec->v, &secVec->v, n);
}

int blsPublicKeyRecover(blsPublicKey *pub, const blsPublicKey *pubVec, const blsId *idVec, mclSize n)
{
	return mclBn_G2LagrangeInterpolation(&pub->v, &idVec->v, &pubVec->v, n);
}

int blsSignatureRecover(blsSignature *sig, const blsSignature *sigVec, const blsId *idVec, mclSize n)
{
	return mclBn_G1LagrangeInterpolation(&sig->v, &idVec->v, &sigVec->v, n);
}

void blsSecretKeyAdd(blsSecretKey *sec, const blsSecretKey *rhs)
{
	mclBnFr_add(&sec->v, &sec->v, &rhs->v);
}

void blsPublicKeyAdd(blsPublicKey *pub, const blsPublicKey *rhs)
{
	mclBnG2_add(&pub->v, &pub->v, &rhs->v);
}

void blsSignatureAdd(blsSignature *sig, const blsSignature *rhs)
{
	mclBnG1_add(&sig->v, &sig->v, &rhs->v);
}

void blsSignatureVerifyOrder(int doVerify)
{
	mclBn_verifyOrderG1(doVerify);
}
void blsPublicKeyVerifyOrder(int doVerify)
{
	mclBn_verifyOrderG2(doVerify);
}
int blsSignatureIsValidOrder(const blsSignature *sig)
{
	return mclBnG1_isValidOrder(&sig->v);
}
int blsPublicKeyIsValidOrder(const blsPublicKey *pub)
{
	return mclBnG2_isValidOrder(&pub->v);
}

#ifndef BLS_MINIMUM_API
inline bool toG1(G1& Hm, const void *h, mclSize size)
{
	Fp t;
	t.setArrayMask((const char *)h, size);
	bool b;
	BN::mapToG1(&b, Hm, t);
	return b;
}

int blsVerifyAggregatedHashes(const blsSignature *aggSig, const blsPublicKey *pubVec, const void *hVec, size_t sizeofHash, mclSize n)
{
	if (n == 0) return 0;
	/*
		e(aggSig, Q) = prod_i e(hVec[i], pubVec[i])
		<=> finalExp(ML(-aggSig, Q) * prod_i ML(hVec[i], pubVec[i])) == 1
	*/
	GT e1, e2;
	BN::precomputedMillerLoop(e1, -*cast(&aggSig->v), g_Qcoeff.data());
	const char *ph = (const char*)hVec;
	G1 h;
	if (!toG1(h, &ph[0], sizeofHash)) return 0;
	BN::millerLoop(e2, h, *cast(&pubVec[0].v));
	e1 *= e2;
	for (size_t i = 1; i < n; i++) {
		if (!toG1(h, &ph[i * sizeofHash], sizeofHash)) return 0;
		BN::millerLoop(e2, h, *cast(&pubVec[i].v));
		e1 *= e2;
	}
	BN::finalExp(e1, e1);
	return e1.isOne();
}

int blsSignHash(blsSignature *sig, const blsSecretKey *sec, const void *h, mclSize size)
{
	G1 Hm;
	if (!toG1(Hm, h, size)) return -1;
	mclBnG1_mulCT(&sig->v, cast(&Hm), &sec->v);
	return 0;
}

int blsVerifyHash(const blsSignature *sig, const blsPublicKey *pub, const void *h, mclSize size)
{
	G1 Hm;
	if (!toG1(Hm, h, size)) return 0;
	return isEqualTwoPairings(*cast(&sig->v), getQcoeff().data(), Hm, *cast(&pub->v));
}

void blsSecretKeySub(blsSecretKey *sec, const blsSecretKey *rhs)
{
	mclBnFr_sub(&sec->v, &sec->v, &rhs->v);
}

void blsPublicKeySub(blsPublicKey *pub, const blsPublicKey *rhs)
{
	mclBnG2_sub(&pub->v, &pub->v, &rhs->v);
}

void blsSignatureSub(blsSignature *sig, const blsSignature *rhs)
{
	mclBnG1_sub(&sig->v, &sig->v, &rhs->v);
}
mclSize blsGetOpUnitSize() // FpUint64Size
{
	return Fp::getUnitSize() * sizeof(mcl::fp::Unit) / sizeof(uint64_t);
}

int blsGetCurveOrder(char *buf, mclSize maxBufSize)
{
	return (int)Fr::getModulo(buf, maxBufSize);
}

int blsGetFieldOrder(char *buf, mclSize maxBufSize)
{
	return (int)Fp::getModulo(buf, maxBufSize);
}

int blsGetG1ByteSize()
{
	return mclBn_getG1ByteSize();
}

int blsGetFrByteSize()
{
	return mclBn_getFrByteSize();
}

void blsGetGeneratorOfG2(blsPublicKey *pub)
{
	*(G2*)pub = getQ();
}

int blsIdSetDecStr(blsId *id, const char *buf, mclSize bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 10);
}
int blsIdSetHexStr(blsId *id, const char *buf, mclSize bufSize)
{
	return mclBnFr_setStr(&id->v, buf, bufSize, 16);
}

int blsIdSetLittleEndian(blsId *id, const void *buf, mclSize bufSize)
{
	return mclBnFr_setLittleEndian(&id->v, buf, bufSize);
}

mclSize blsIdGetDecStr(char *buf, mclSize maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 10);
}

mclSize blsIdGetHexStr(char *buf, mclSize maxBufSize, const blsId *id)
{
	return mclBnFr_getStr(buf, maxBufSize, &id->v, 16);
}

int blsHashToSecretKey(blsSecretKey *sec, const void *buf, mclSize bufSize)
{
	return mclBnFr_setHashOf(&sec->v, buf, bufSize);
}

#ifndef MCL_DONT_USE_CSPRNG
int blsSecretKeySetByCSPRNG(blsSecretKey *sec)
{
	return mclBnFr_setByCSPRNG(&sec->v);
}
#endif

void blsGetPop(blsSignature *sig, const blsSecretKey *sec)
{
	blsPublicKey pub;
	blsGetPublicKey(&pub, sec);
	char buf[1024];
	mclSize n = mclBnG2_serialize(buf, sizeof(buf), &pub.v);
	assert(n);
	blsSign(sig, sec, buf, n);
}

int blsVerifyPop(const blsSignature *sig, const blsPublicKey *pub)
{
	char buf[1024];
	mclSize n = mclBnG2_serialize(buf, sizeof(buf), &pub->v);
	if (n == 0) return 0;
	return blsVerify(sig, pub, buf, n);
}

mclSize blsIdGetLittleEndian(void *buf, mclSize maxBufSize, const blsId *id)
{
	return mclBnFr_serialize(buf, maxBufSize, &id->v);
}
int blsSecretKeySetDecStr(blsSecretKey *sec, const char *buf, mclSize bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 10);
}
int blsSecretKeySetHexStr(blsSecretKey *sec, const char *buf, mclSize bufSize)
{
	return mclBnFr_setStr(&sec->v, buf, bufSize, 16);
}
mclSize blsSecretKeyGetLittleEndian(void *buf, mclSize maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_serialize(buf, maxBufSize, &sec->v);
}
mclSize blsSecretKeyGetDecStr(char *buf, mclSize maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 10);
}
mclSize blsSecretKeyGetHexStr(char *buf, mclSize maxBufSize, const blsSecretKey *sec)
{
	return mclBnFr_getStr(buf, maxBufSize, &sec->v, 16);
}
int blsPublicKeySetHexStr(blsPublicKey *pub, const char *buf, mclSize bufSize)
{
	return mclBnG2_setStr(&pub->v, buf, bufSize, 16);
}
mclSize blsPublicKeyGetHexStr(char *buf, mclSize maxBufSize, const blsPublicKey *pub)
{
	return mclBnG2_getStr(buf, maxBufSize, &pub->v, 16);
}
int blsSignatureSetHexStr(blsSignature *sig, const char *buf, mclSize bufSize)
{
	return mclBnG1_setStr(&sig->v, buf, bufSize, 16);
}
mclSize blsSignatureGetHexStr(char *buf, mclSize maxBufSize, const blsSignature *sig)
{
	return mclBnG1_getStr(buf, maxBufSize, &sig->v, 16);
}
void blsDHKeyExchange(blsPublicKey *out, const blsSecretKey *sec, const blsPublicKey *pub)
{
	mclBnG2_mulCT(&out->v, &pub->v, &sec->v);
}

#endif

