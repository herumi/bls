package bls

/*
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4
#cgo bn256 LDFLAGS:-lbls256
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn384 LDFLAGS:-lbls384
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4
#cgo bn384_256 LDFLAGS:-lbls384_256
#cgo LDFLAGS:-lcrypto -lgmp -lgmpxx -lstdc++

#cgo bn256_swapg CFLAGS:-DMCLBN_FP_UNIT_SIZE=4 -DBLS_SWAP_G
#cgo bn256_swapg LDFLAGS:-lbls256
#cgo bn384_swapg CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DBLS_SWAP_G
#cgo bn384_swapg LDFLAGS:-lbls384
#cgo bn384_256_swapg CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_SWAP_G
#cgo bn384_256_swapg LDFLAGS:-lbls384_256
#cgo LDFLAGS:-lcrypto -lgmp -lgmpxx -lstdc++
typedef unsigned int (*ReadRandFunc)(void *, void *, unsigned int);
int wrapReadRandCgo(void *self, void *buf, unsigned int n);
#include <bls/bls.h>
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"unsafe"
)

func hex2byte(s string) ([]byte, error) {
	if (len(s) & 1) == 1 {
		return nil, fmt.Errorf("odd length")
	}
	return hex.DecodeString(s)
}

// Init --
// call this function before calling all the other operations
// this function is not thread safe
func Init(curve int) error {
	err := C.blsInit(C.int(curve), C.MCLBN_COMPILED_TIME_VAR)
	if err != 0 {
		return fmt.Errorf("ERR Init curve=%d", curve)
	}
	return nil
}

// ID --
type ID struct {
	v C.blsId
}

// Serialize --
func (id *ID) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsIdSerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdSerialize")
	}
	return buf[:n]
}

// Deserialize --
func (id *ID) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsIdDeserialize(&id.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsIdDeserialize %x", buf)
	}
	return nil
}

// GetLittleEndian -- alias of Serialize
func (id *ID) GetLittleEndian() []byte {
	return id.Serialize()
}

// SetLittleEndian --
func (id *ID) SetLittleEndian(buf []byte) error {
	// #nosec
	err := C.blsIdSetLittleEndian(&id.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetLittleEndian %x", err)
	}
	return nil
}

// SerializeToHexStr --
func (id *ID) SerializeToHexStr() string {
	return hex.EncodeToString(id.Serialize())
}

// DeserializeHexStr --
func (id *ID) DeserializeHexStr(s string) error {
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return id.Deserialize(a)
}

// GetHexString --
func (id *ID) GetHexString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsIdGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetHexStr")
	}
	return string(buf[:n])
}

// GetDecString --
func (id *ID) GetDecString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsIdGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetDecStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (id *ID) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsIdSetHexStr(&id.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetHexStr %s", s)
	}
	return nil
}

// SetDecString --
func (id *ID) SetDecString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsIdSetDecStr(&id.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetDecStr %s", s)
	}
	return nil
}

// IsEqual --
func (id *ID) IsEqual(rhs *ID) bool {
	if id == nil || rhs == nil {
		return false
	}
	return C.blsIdIsEqual(&id.v, &rhs.v) == 1
}

// SecretKey --
type SecretKey struct {
	v C.blsSecretKey
}

// Serialize --
func (sec *SecretKey) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsSecretKeySerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &sec.v)
	if n == 0 {
		panic("err blsSecretKeySerialize")
	}
	return buf[:n]
}

// Deserialize --
func (sec *SecretKey) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsSecretKeyDeserialize(&sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsSecretKeyDeserialize %x", buf)
	}
	return nil
}

// GetLittleEndian -- alias of Serialize
func (sec *SecretKey) GetLittleEndian() []byte {
	return sec.Serialize()
}

// SetLittleEndian --
func (sec *SecretKey) SetLittleEndian(buf []byte) error {
	// #nosec
	err := C.blsSecretKeySetLittleEndian(&sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndian %x", err)
	}
	return nil
}

// SetLittleEndianMod --
func (sec *SecretKey) SetLittleEndianMod(buf []byte) error {
	// #nosec
	err := C.blsSecretKeySetLittleEndianMod(&sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndianMod %x", err)
	}
	return nil
}

// SerializeToHexStr --
func (sec *SecretKey) SerializeToHexStr() string {
	return hex.EncodeToString(sec.Serialize())
}

// DeserializeHexStr --
func (sec *SecretKey) DeserializeHexStr(s string) error {
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return sec.Deserialize(a)
}

// GetHexString --
func (sec *SecretKey) GetHexString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsSecretKeyGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &sec.v)
	if n == 0 {
		panic("err blsSecretKeyGetHexStr")
	}
	return string(buf[:n])
}

// GetDecString --
func (sec *SecretKey) GetDecString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsSecretKeyGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &sec.v)
	if n == 0 {
		panic("err blsSecretKeyGetDecStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (sec *SecretKey) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSecretKeySetHexStr(&sec.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetHexStr %s", s)
	}
	return nil
}

// SetDecString --
func (sec *SecretKey) SetDecString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSecretKeySetDecStr(&sec.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetDecStr %s", s)
	}
	return nil
}

// IsEqual --
func (sec *SecretKey) IsEqual(rhs *SecretKey) bool {
	if sec == nil || rhs == nil {
		return false
	}
	return C.blsSecretKeyIsEqual(&sec.v, &rhs.v) == 1
}

// SetByCSPRNG --
func (sec *SecretKey) SetByCSPRNG() {
	err := C.blsSecretKeySetByCSPRNG(&sec.v)
	if err != 0 {
		panic("err blsSecretKeySetByCSPRNG")
	}
}

// Add --
func (sec *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(&sec.v, &rhs.v)
}

// GetMasterSecretKey --
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].SetByCSPRNG()
	}
	return msk
}

// GetMasterPublicKey --
func GetMasterPublicKey(msk []SecretKey) (mpk []PublicKey) {
	n := len(msk)
	mpk = make([]PublicKey, n)
	for i := 0; i < n; i++ {
		mpk[i] = *msk[i].GetPublicKey()
	}
	return mpk
}

// Set --
func (sec *SecretKey) Set(msk []SecretKey, id *ID) error {
	// #nosec
	ret := C.blsSecretKeyShare(&sec.v, &msk[0].v, (C.mclSize)(len(msk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyShare")
	}
	return nil
}

// Recover --
func (sec *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	if len(secVec) != len(idVec) {
		return fmt.Errorf("err SecretKey.Recover bad size")
	}
	// #nosec
	ret := C.blsSecretKeyRecover(&sec.v, &secVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(len(idVec)))
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyRecover")
	}
	return nil
}

// GetPop --
func (sec *SecretKey) GetPop() (sig *Sign) {
	sig = new(Sign)
	C.blsGetPop(&sig.v, &sec.v)
	return sig
}

// ToFr --
func (sec *SecretKey) ToFr() *Fr {
	f := &Fr{v: sec.v.v}
	return f
}

// SetFr --
func (sec *SecretKey) SetFr(f *Fr) {
	sec.v.v = f.v
}

// PublicKey --
type PublicKey struct {
	v C.blsPublicKey
}

// PublicKeys ..
type PublicKeys []PublicKey

// JSON provides a JSON string dump of slice of PublicKeys in Hexformat
func (keys PublicKeys) JSON() string {
	type T struct {
		Count      int      `json:"count"`
		PublicKeys []string `json:"public-keys"`
	}
	t := T{len(keys), make([]string, len(keys))}
	for i := range keys {
		t.PublicKeys[i] = keys[i].SerializeToHexStr()
	}
	b, _ := json.Marshal(t)
	return string(b)
}

// Serialize --
func (pub *PublicKey) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsPublicKeySerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &pub.v)
	if n == 0 {
		panic("err blsPublicKeySerialize")
	}
	return buf[:n]
}

// Deserialize --
func (pub *PublicKey) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsPublicKeyDeserialize(&pub.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsPublicKeyDeserialize %x", buf)
	}
	return nil
}

// SerializeToHexStr --
func (pub *PublicKey) SerializeToHexStr() string {
	return hex.EncodeToString(pub.Serialize())
}

// DeserializeHexStr --
func (pub *PublicKey) DeserializeHexStr(s string) error {
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return pub.Deserialize(a)
}

// GetHexString --
func (pub *PublicKey) GetHexString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsPublicKeyGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &pub.v)
	if n == 0 {
		panic("err blsPublicKeyGetHexStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (pub *PublicKey) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsPublicKeySetHexStr(&pub.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsPublicKeySetHexStr %s", s)
	}
	return nil
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	if pub == nil || rhs == nil {
		return false
	}
	return C.blsPublicKeyIsEqual(&pub.v, &rhs.v) == 1
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(&pub.v, &rhs.v)
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	// #nosec
	ret := C.blsPublicKeyShare(&pub.v, &mpk[0].v, (C.mclSize)(len(mpk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyShare")
	}
	return nil
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	if len(pubVec) != len(idVec) {
		return fmt.Errorf("err PublicKey.Recover bad size")
	}
	// #nosec
	ret := C.blsPublicKeyRecover(&pub.v, &pubVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(len(idVec)))
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyRecover")
	}
	return nil
}

// ToG1 --
func (pub *PublicKey) ToG1() *G1 {
	switch v := interface{}(pub.v.v).(type) {
	case C.mclBnG1:
		g := &G1{}
		*(g.getPointer()) = v
		return g
	default:
		panic("cannot cast PK to G1")
	}
}

// SetG1 --
func (pub *PublicKey) SetG1(g *G1) {
	switch p := interface{}(&pub.v.v).(type) {
	case *C.mclBnG1:
		*p = *(g.getPointer())
	default:
		panic("cannot cast G1 to PK")
	}
}

// ToG2 --
func (pub *PublicKey) ToG2() *G2 {
	switch v := interface{}(pub.v.v).(type) {
	case C.mclBnG2:
		g := &G2{}
		*(g.getPointer()) = v
		return g
	default:
		panic("cannot cast PK to G2")
	}
}

// SetG2 --
func (pub *PublicKey) SetG2(g *G2) {
	switch p := interface{}(&pub.v.v).(type) {
	case *C.mclBnG2:
		*p = *(g.getPointer())
	default:
		panic("cannot cast G2 to PK")
	}
}

// Sign  --
type Sign struct {
	v C.blsSignature
}

// Serialize --
func (sig *Sign) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsSignatureSerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &sig.v)
	if n == 0 {
		panic("err blsSignatureSerialize")
	}
	return buf[:n]
}

// Deserialize --
func (sig *Sign) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsSignatureDeserialize(&sig.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsSignatureDeserialize %x", buf)
	}
	return nil
}

// SerializeToHexStr --
func (sig *Sign) SerializeToHexStr() string {
	return hex.EncodeToString(sig.Serialize())
}

// DeserializeHexStr --
func (sig *Sign) DeserializeHexStr(s string) error {
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return sig.Deserialize(a)
}

// GetHexString --
func (sig *Sign) GetHexString() string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.blsSignatureGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &sig.v)
	if n == 0 {
		panic("err blsSignatureGetHexStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (sig *Sign) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSignatureSetHexStr(&sig.v, (*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSignatureSetHexStr %s", s)
	}
	return nil
}

// IsEqual --
func (sig *Sign) IsEqual(rhs *Sign) bool {
	if sig == nil || rhs == nil {
		return false
	}
	return C.blsSignatureIsEqual(&sig.v, &rhs.v) == 1
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(&pub.v, &sec.v)
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(m string) (sig *Sign) {
	sig = new(Sign)
	buf := []byte(m)
	// #nosec
	C.blsSign(&sig.v, &sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	return sig
}

// Add --
func (sig *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(&sig.v, &rhs.v)
}

// Recover --
func (sig *Sign) Recover(sigVec []Sign, idVec []ID) error {
	if len(sigVec) != len(idVec) {
		return fmt.Errorf("err Sign.Recover bad size")
	}
	// #nosec
	ret := C.blsSignatureRecover(&sig.v, &sigVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(len(idVec)))
	if ret != 0 {
		return fmt.Errorf("err blsSignatureRecover")
	}
	return nil
}

// Verify --
func (sig *Sign) Verify(pub *PublicKey, m string) bool {
	if sig == nil || pub == nil {
		return false
	}
	buf := []byte(m)
	// #nosec
	return C.blsVerify(&sig.v, &pub.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf))) == 1
}

// ToG1 --
func (sig *Sign) ToG1() *G1 {
	switch v := interface{}(sig.v.v).(type) {
	case C.mclBnG1:
		g := &G1{}
		*(g.getPointer()) = v
		return g
	default:
		panic("cannot cast SIG to G2")
	}
}

// SetG1 --
func (sig *Sign) SetG1(g *G1) {
	switch p := interface{}(&sig.v.v).(type) {
	case *C.mclBnG1:
		*p = *(g.getPointer())
	default:
		panic("cannot cast G1 to SIG")
	}
}

// ToG2 --
func (sig *Sign) ToG2() *G2 {
	switch v := interface{}(sig.v.v).(type) {
	case C.mclBnG2:
		g := &G2{}
		*(g.getPointer()) = v
		return g
	default:
		panic("cannot cast SIG to G2")
	}
}

// SetG2 --
func (sig *Sign) SetG2(g *G2) {
	switch p := interface{}(&sig.v.v).(type) {
	case *C.mclBnG2:
		*p = *(g.getPointer())
	default:
		panic("cannot cast G2 to SIG")
	}
}

func bool2int(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// VerifySignatureOrder --
func VerifySignatureOrder(doVerify bool) {
	C.blsSignatureVerifyOrder(bool2int(doVerify))
}

// VerifyPublicKeyOrder --
func VerifyPublicKeyOrder(doVerify bool) {
	C.blsPublicKeyVerifyOrder(bool2int(doVerify))
}

// IsValidOrder --
func (pub *PublicKey) IsValidOrder() bool {
	return C.blsPublicKeyIsValidOrder(&pub.v) == 1
}

// IsValidOrder --
func (sig *Sign) IsValidOrder() bool {
	return C.blsSignatureIsValidOrder(&sig.v) == 1
}

// VerifyPop --
func (sig *Sign) VerifyPop(pub *PublicKey) bool {
	if sig == nil || pub == nil {
		return false
	}
	return C.blsVerifyPop(&sig.v, &pub.v) == 1
}

// DHKeyExchange --
func DHKeyExchange(sec *SecretKey, pub *PublicKey) (out PublicKey) {
	C.blsDHKeyExchange(&out.v, &sec.v, &pub.v)
	return out
}

// HashAndMapToSignature --
func HashAndMapToSignature(buf []byte) *Sign {
	sig := new(Sign)
	// #nosec
	err := C.blsHashToSignature(&sig.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return nil
	}
	return sig
}

// VerifyPairing --
func VerifyPairing(X *Sign, Y *Sign, pub *PublicKey) bool {
	if X == nil || Y == nil || pub == nil {
		return false
	}
	return C.blsVerifyPairing(&X.v, &Y.v, &pub.v) == 1
}

// SignHash --
func (sec *SecretKey) SignHash(hash []byte) (sig *Sign) {
	sig = new(Sign)
	// #nosec
	err := C.blsSignHash(&sig.v, &sec.v, unsafe.Pointer(&hash[0]), C.mclSize(len(hash)))
	if err == 0 {
		return sig
	}
	return nil
}

// VerifyHash --
func (sig *Sign) VerifyHash(pub *PublicKey, hash []byte) bool {
	if pub == nil {
		return false
	}
	// #nosec
	return C.blsVerifyHash(&sig.v, &pub.v, unsafe.Pointer(&hash[0]), C.mclSize(len(hash))) == 1
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// VerifyAggregateHashes --
func (sig *Sign) VerifyAggregateHashes(pubVec []PublicKey, hash [][]byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(hash)
	if n == 0 {
		return false
	}
	hashByte := len(hash[0])
	h := make([]byte, n*hashByte)
	for i := 0; i < n; i++ {
		hn := len(hash[i])
		copy(h[i*hashByte:(i+1)*hashByte], hash[i][0:min(hn, hashByte)])
	}
	return C.blsVerifyAggregatedHashes(&sig.v, &pubVec[0].v, unsafe.Pointer(&h[0]), C.mclSize(hashByte), C.mclSize(n)) == 1
}

// SignHashWithDomain --
func (sec *SecretKey) SignHashWithDomain(hashWithDomain []byte) (sig *Sign) {
	if len(hashWithDomain) != 40 {
		return nil
	}
	sig = new(Sign)
	// #nosec
	err := C.blsSignHashWithDomain(&sig.v, &sec.v, (*C.uchar)(unsafe.Pointer(&hashWithDomain[0])))
	if err == 0 {
		return sig
	}
	return nil
}

// VerifyHashWithDomain --
func (sig *Sign) VerifyHashWithDomain(pub *PublicKey, hashWithDomain []byte) bool {
	if len(hashWithDomain) != 40 {
		return false
	}
	if pub == nil {
		return false
	}
	// #nosec
	return C.blsVerifyHashWithDomain(&sig.v, &pub.v, (*C.uchar)(unsafe.Pointer(&hashWithDomain[0]))) == 1
}

// VerifyAggregateHashWithDomain --
// hashWithDomains is array of 40 * len(pubVec)
func (sig *Sign) VerifyAggregateHashWithDomain(pubVec []PublicKey, hashWithDomains []byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(pubVec)
	if n == 0 || len(hashWithDomains) != n*40 {
		return false
	}
	return C.blsVerifyAggregatedHashWithDomain(&sig.v, &pubVec[0].v, (*[40]C.uchar)(unsafe.Pointer(&hashWithDomains[0])), C.mclSize(n)) == 1
}

///

var sRandReader io.Reader

func createSlice(buf *C.char, n C.uint) []byte {
	size := int(n)
	return (*[1 << 30]byte)(unsafe.Pointer(buf))[:size:size]
}

// this function can't be put in callback.go
//export wrapReadRandGo
func wrapReadRandGo(buf *C.char, n C.uint) C.uint {
	slice := createSlice(buf, n)
	ret, err := sRandReader.Read(slice)
	if ret == int(n) && err == nil {
		return n
	}
	return 0
}

// SetRandFunc --
func SetRandFunc(randReader io.Reader) {
	sRandReader = randReader
	if randReader != nil {
		C.blsSetRandFunc(nil, C.ReadRandFunc(unsafe.Pointer(C.wrapReadRandCgo)))
	} else {
		// use default random generator
		C.blsSetRandFunc(nil, C.ReadRandFunc(unsafe.Pointer(nil)))
	}
}

func IsSwapG() bool {
	pk := C.blsPublicKey{}
	v := interface{}(pk.v)
	switch v.(type) {
	case C.mclBnG1:
		return true
	case C.mclBnG2:
		return false
	}
	panic("unable to determine library swap")
}
