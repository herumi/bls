package bls

/*
#cgo CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo LDFLAGS:-lbls384_dy -lgmpxx -lstdc++ -lgmp -lcrypto
#include <bls/bls.h>
*/
import "C"
import "fmt"
import "unsafe"

// Init --
// call this function before calling all the other operations
// this function is not thread safe
func Init(curve int) error {
	err := C.blsInit(C.int(curve), C.MCLBN_FP_UNIT_SIZE)
	if err != 0 {
		return fmt.Errorf("ERR Init curve=%d", curve)
	}
	return nil
}

// GetMaxOpUnitSize --
func GetMaxOpUnitSize() int {
	return int(C.MCLBN_FP_UNIT_SIZE)
}

// GetOpUnitSize --
func GetOpUnitSize() int {
	return int(C.blsGetOpUnitSize())
}

// GetCurveOrder --
func GetCurveOrder() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsGetCurveOrder((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

// GetFieldOrder --
func GetFieldOrder() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsGetFieldOrder((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

// ID --
type ID struct {
	v C.mclBnFr
}

// getPointer --
func (id *ID) getPointer() (p *C.blsId) {
	// #nosec
	return (*C.blsId)(unsafe.Pointer(id))
}

// GetLittleEndian --
func (id *ID) GetLittleEndian() []byte {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsIdGetLittleEndian(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), id.getPointer())
	if n == 0 {
		panic("err blsIdGetLittleEndian")
	}
	return buf[:n]
}

// SetLittleEndian --
func (id *ID) SetLittleEndian(buf []byte) error {
	// #nosec
	err := C.blsIdSetLittleEndian(id.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetLittleEndian %x", err)
	}
	return nil
}

// GetHexString --
func (id *ID) GetHexString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsIdGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), id.getPointer())
	if n == 0 {
		panic("err blsIdGetHexStr")
	}
	return string(buf[:n])
}

// GetDecString --
func (id *ID) GetDecString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsIdGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), id.getPointer())
	if n == 0 {
		panic("err blsIdGetDecStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (id *ID) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsIdSetHexStr(id.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetHexStr %x", err)
	}
	return nil
}

// SetDecString --
func (id *ID) SetDecString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsIdSetDecStr(id.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetDecStr %x", buf)
	}
	return nil
}

// IsEqual --
func (id *ID) IsEqual(rhs *ID) bool {
	return C.blsIdIsEqual(id.getPointer(), rhs.getPointer()) == 1
}

// SecretKey --
type SecretKey struct {
	v C.mclBnFr
}

// getPointer --
func (sec *SecretKey) getPointer() (p *C.blsSecretKey) {
	// #nosec
	return (*C.blsSecretKey)(unsafe.Pointer(sec))
}

// GetLittleEndian --
func (sec *SecretKey) GetLittleEndian() []byte {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsSecretKeyGetLittleEndian(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), sec.getPointer())
	if n == 0 {
		panic("err blsSecretKeyGetLittleEndian")
	}
	return buf[:n]
}

// SetLittleEndian --
func (sec *SecretKey) SetLittleEndian(buf []byte) error {
	// #nosec
	err := C.blsSecretKeySetLittleEndian(sec.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndian %x", buf)
	}
	return nil
}

// GetHexString --
func (sec *SecretKey) GetHexString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsSecretKeyGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), sec.getPointer())
	if n == 0 {
		panic("err blsSecretKeyGetHexStr")
	}
	return string(buf[:n])
}

// GetDecString --
func (sec *SecretKey) GetDecString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsSecretKeyGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), sec.getPointer())
	if n == 0 {
		panic("err blsSecretKeyGetDecStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (sec *SecretKey) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSecretKeySetHexStr(sec.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("erre blsSecretKeySetHexStr %s", s)
	}
	return nil
}

// SetDecString --
func (sec *SecretKey) SetDecString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSecretKeySetDecStr(sec.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("erre blsSecretKeySetDecStr %s", s)
	}
	return nil
}

// IsEqual --
func (sec *SecretKey) IsEqual(rhs *SecretKey) bool {
	return C.blsSecretKeyIsEqual(sec.getPointer(), rhs.getPointer()) == 1
}

// Init --
func (sec *SecretKey) Init() {
	C.blsSecretKeySetByCSPRNG(sec.getPointer())
}

// Add --
func (sec *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(sec.getPointer(), rhs.getPointer())
}

// GetMasterSecretKey --
func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].Init()
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
	err := C.blsSecretKeyShare(sec.getPointer(), msk[0].getPointer(), C.size_t(len(msk)), id.getPointer())
	if err != 0 {
		return fmt.Errorf("err blsSecretKeyShare id %s", id.GetHexString())
	}
	return nil
}

// Recover --
func (sec *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	err := C.blsSecretKeyRecover(sec.getPointer(), secVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(secVec)))
	if err != 0 {
		return fmt.Errorf("SecretKey.Recover")
	}
	return nil
}

// GetPop --
func (sec *SecretKey) GetPop() (sign *Sign) {
	sign = new(Sign)
	C.blsGetPop(sign.getPointer(), sec.getPointer())
	return sign
}

// PublicKey --
type PublicKey struct {
	v C.mclBnG2
}

// getPointer --
func (pub *PublicKey) getPointer() (p *C.blsPublicKey) {
	// #nosec
	return (*C.blsPublicKey)(unsafe.Pointer(pub))
}

// Serialize --
func (pub *PublicKey) Serialize() []byte {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsPublicKeySerialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), pub.getPointer())
	if n == 0 {
		panic("err blsPublicKeySerialize")
	}
	return buf[:n]
}

// Deserialize --
func (pub *PublicKey) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsPublicKeyDeserialize(pub.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsPublicKeyDeserialize %x", buf)
	}
	return nil
}

// GetHexString --
func (pub *PublicKey) GetHexString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsPublicKeyGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), pub.getPointer())
	if n == 0 {
		panic("err blsPublicKeyGetHexStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (pub *PublicKey) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsPublicKeySetHexStr(pub.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsPublicKeySetHexStr %x", buf)
	}
	return nil
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	return C.blsPublicKeyIsEqual(pub.getPointer(), rhs.getPointer()) == 1
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(pub.getPointer(), rhs.getPointer())
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	err := C.blsPublicKeyShare(pub.getPointer(), mpk[0].getPointer(), C.size_t(len(mpk)), id.getPointer())
	if err != 0 {
		return fmt.Errorf("PublicKey.set")
	}
	return nil
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	err := C.blsPublicKeyRecover(pub.getPointer(), pubVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(pubVec)))
	if err != 0 {
		return fmt.Errorf("PublicKey.Recover")
	}
	return nil
}

// Sign  --
type Sign struct {
	v C.mclBnG1
}

// getPointer --
func (sign *Sign) getPointer() (p *C.blsSignature) {
	// #nosec
	return (*C.blsSignature)(unsafe.Pointer(sign))
}

// Serialize --
func (sign *Sign) Serialize() []byte {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsSignatureSerialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), sign.getPointer())
	if n == 0 {
		panic("err blsSignatureSerialize")
	}
	return buf[:n]
}

// Deserialize --
func (sign *Sign) Deserialize(buf []byte) error {
	// #nosec
	err := C.blsSignatureDeserialize(sign.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSignatureDeserialize %x", buf)
	}
	return nil
}

// GetHexString --
func (sign *Sign) GetHexString() string {
	buf := make([]byte, 1024)
	// #nosec
	n := C.blsSignatureGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), sign.getPointer())
	if n == 0 {
		panic("err blsSignatureGetHexStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (sign *Sign) SetHexString(s string) error {
	buf := []byte(s)
	// #nosec
	err := C.blsSignatureSetHexStr(sign.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSignatureSetHexStr %x", buf)
	}
	return nil
}

// IsEqual --
func (sign *Sign) IsEqual(rhs *Sign) bool {
	return C.blsSignatureIsEqual(sign.getPointer(), rhs.getPointer()) == 1
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsGetPublicKey(pub.getPointer(), sec.getPointer())
	return pub
}

// Sign -- Constant Time version
func (sec *SecretKey) Sign(m string) (sign *Sign) {
	sign = new(Sign)
	buf := []byte(m)
	// #nosec
	C.blsSign(sign.getPointer(), sec.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return sign
}

// Add --
func (sign *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(sign.getPointer(), rhs.getPointer())
}

// Recover --
func (sign *Sign) Recover(signVec []Sign, idVec []ID) error {
	err := C.blsSignatureRecover(sign.getPointer(), signVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(signVec)))
	if err != 0 {
		return fmt.Errorf("Sign.Recover")
	}
	return nil
}

// Verify --
func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	buf := []byte(m)
	// #nosec
	return C.blsVerify(sign.getPointer(), pub.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) == 1
}

// VerifyPop --
func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsVerifyPop(sign.getPointer(), pub.getPointer()) == 1
}
