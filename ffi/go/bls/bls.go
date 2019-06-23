package bls

/*
#cgo CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_SWAP_G
#cgo LDFLAGS:-lbls384_256 -lcrypto -lgmp -lgmpxx -lstdc++
typedef unsigned int (*ReadRandFunc)(void *, void *, unsigned int);
int wrapReadRandCgo(void *self, void *buf, unsigned int n);
#include <bls/bls.h>
*/
import "C"
import "errors"
import "fmt"
import "unsafe"
import "io"
import "crypto/sha256"
import "encoding/hex"

// We need to run this before any bls usage externally.
func init() {
	Init(BLS12_381)
}

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

// GetAddress --
func (pub *PublicKey) GetAddress() [20]byte {
	address := [20]byte{}
	hash := sha256.Sum256(pub.Serialize())
	copy(address[:], hash[:20])
	return address
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
	if len(buf) == 0 {
		return fmt.Errorf("Empty bytes")
	}
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
	if len(buf) == 0 {
		return fmt.Errorf("Empty bytes")
	}
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
	if sec == nil {
		return []byte{}
	}
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
	if sec == nil {
		return fmt.Errorf("err nil secret key")
	}
	if len(buf) == 0 {
		return fmt.Errorf("Empty bytes")
	}
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
	if sec == nil {
		return fmt.Errorf("err nil secret key")
	}
	if len(buf) == 0 {
		return fmt.Errorf("Empty bytes")
	}
	// #nosec
	err := C.blsSecretKeySetLittleEndian(&sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndian %x", err)
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
	if sec == nil || rhs == nil {
		return
	}
	C.blsSecretKeyAdd(&sec.v, &rhs.v)
}

// GetMasterSecretKey --
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	if k == 0 {
		return msk
	}
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
	if sec == nil {
		return fmt.Errorf("err nil secret key")
	}
	if len(msk) == 0 {
		return fmt.Errorf("Empty msk")
	}
	// #nosec
	ret := C.blsSecretKeyShare(&sec.v, &msk[0].v, (C.mclSize)(len(msk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyShare")
	}
	return nil
}

// Recover --
func (sec *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	if sec == nil {
		return fmt.Errorf("err nil secret key")
	}
	if len(secVec) != len(idVec) {
		return fmt.Errorf("err SecretKey.Recover bad size")
	}
	if len(secVec) == 0 {
		return fmt.Errorf("Empty secVec")
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
	if sec == nil {
		return nil
	}
	sig = new(Sign)
	C.blsGetPop(&sig.v, &sec.v)
	return sig
}

// PublicKey --
type PublicKey struct {
	v C.blsPublicKey
}

// Serialize --
func (pub *PublicKey) Serialize() []byte {
	if pub == nil {
		return []byte{}
	}
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
	if pub == nil {
		return errors.New("Public key is nil.")
	}
	if len(buf) == 0 {
		return errors.New("Empty bytes")
	}
	// #nosec
	err := C.blsPublicKeyDeserialize(&pub.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsPublicKeyDeserialize %x", buf)
	}
	return nil
}

// SerializeToHexStr --
func (pub *PublicKey) SerializeToHexStr() string {
	if pub == nil {
		return ""
	}
	return hex.EncodeToString(pub.Serialize())
}

// DeserializeHexStr --
func (pub *PublicKey) DeserializeHexStr(s string) error {
	if pub == nil {
		return errors.New("Public key is nil.")
	}
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return pub.Deserialize(a)
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
	if pub == nil || rhs == nil {
		return
	}
	C.blsPublicKeyAdd(&pub.v, &rhs.v)
}

// Sub --
func (pub *PublicKey) Sub(rhs *PublicKey) {
	if pub == nil || rhs == nil {
		return
	}
	C.blsPublicKeySub(&pub.v, &rhs.v)
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	if pub == nil {
		return errors.New("err nil public key")
	}
	if len(mpk) == 0 {
		return errors.New("Empty mpk")
	}
	// #nosec
	ret := C.blsPublicKeyShare(&pub.v, &mpk[0].v, (C.mclSize)(len(mpk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyShare")
	}
	return nil
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	if pub == nil {
		return errors.New("err nil public key")
	}
	if len(pubVec) != len(idVec) {
		return fmt.Errorf("err PublicKey.Recover bad size")
	}
	if len(pubVec) == 0 {
		return errors.New("Empty pubVec")
	}
	// #nosec
	ret := C.blsPublicKeyRecover(&pub.v, &pubVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(len(idVec)))
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyRecover")
	}
	return nil
}

// Sign  --
type Sign struct {
	v C.blsSignature
}

// Serialize --
func (sig *Sign) Serialize() []byte {
	if sig == nil {
		return []byte{}
	}
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
	if sig == nil {
		return errors.New("Signature is nil.")
	}
	if len(buf) == 0 {
		return errors.New("Empty buf")
	}
	// #nosec
	err := C.blsSignatureDeserialize(&sig.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	if err == 0 {
		return fmt.Errorf("err blsSignatureDeserialize %x", buf)
	}
	return nil
}

// SerializeToHexStr --
func (sig *Sign) SerializeToHexStr() string {
	if sig == nil {
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// DeserializeHexStr --
func (sig *Sign) DeserializeHexStr(s string) error {
	if sig == nil {
		return errors.New("Signature is nil.")
	}
	a, err := hex2byte(s)
	if err != nil {
		return err
	}
	return sig.Deserialize(a)
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
	if sec == nil {
		return nil
	}
	pub = new(PublicKey)
	C.blsGetPublicKey(&pub.v, &sec.v)
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(m string) (sig *Sign) {
	if sec == nil {
		return nil
	}
	sig = new(Sign)
	buf := []byte(m)
	// #nosec
	C.blsSign(&sig.v, &sec.v, unsafe.Pointer(&buf[0]), C.mclSize(len(buf)))
	return sig
}

// Add --
func (sig *Sign) Add(rhs *Sign) {
	if sig == nil {
		return
	}
	C.blsSignatureAdd(&sig.v, &rhs.v)
}

// Recover --
func (sig *Sign) Recover(sigVec []Sign, idVec []ID) error {
	if sig == nil {
		return fmt.Errorf("err nil signature")
	}
	if len(sigVec) != len(idVec) {
		return fmt.Errorf("err Sign.Recover bad size")
	}
	if len(sigVec) == 0 {
		return errors.New("Empty sigVec")
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
	if sec == nil {
		return nil
	}
	sig = new(Sign)
	if len(hash) == 0 {
		return nil
	}
	// #nosec
	err := C.blsSignHash(&sig.v, &sec.v, unsafe.Pointer(&hash[0]), C.mclSize(len(hash)))
	if err == 0 {
		return sig
	}
	return nil
}

// VerifyHash --
func (sig *Sign) VerifyHash(pub *PublicKey, hash []byte) bool {
	if sig == nil {
		return false
	}
	if pub == nil {
		return false
	}
	if len(hash) == 0 {
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
	if sig == nil {
		return false
	}
	if pubVec == nil || len(pubVec) == 0{
		return false
	}
	n := len(hash)
	if n == 0 {
		return false
	}
	hashByte := GetOpUnitSize() * 8
	h := make([]byte, n*hashByte)
	for i := 0; i < n; i++ {
		hn := len(hash[i])
		copy(h[i*hashByte:(i+1)*hashByte], hash[i][0:min(hn, hashByte)])
	}
	return C.blsVerifyAggregatedHashes(&sig.v, &pubVec[0].v, unsafe.Pointer(&h[0]), C.mclSize(hashByte), C.mclSize(n)) == 1
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
