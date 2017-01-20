package bls

/*
#cgo CFLAGS:-I../../include
#cgo LDFLAGS:-lbls -lbls_if -lmcl -lgmp -lgmpxx -L../lib -L../../lib -L../../../mcl/lib -L../../mcl/lib  -lstdc++ -lcrypto
#include "bls_if.h"
*/
import "C"
import "fmt"
import "unsafe"

func Init() {
	C.blsInit()
}

type Id struct {
	v [4]C.uint64_t
}

func (id *Id) getPointer() (p *C.blsId) {
	return (*C.blsId)(unsafe.Pointer(&id.v[0]))
}

func (id *Id) String() string {
	buf := make([]byte, 1024)
	n := C.blsIdGetStr(id.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (id *Id) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsIdSetStr(id.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (id *Id) Set(v []uint64) error {
	if len(v) != 4 {
		return fmt.Errorf("bad size", len(v))
	}
	C.blsIdSet(id.getPointer(), (*C.uint64_t)(unsafe.Pointer(&v[0])))
	return nil
}

type SecretKey struct {
	v [4]C.uint64_t
}

func (sec *SecretKey) getPointer() (p *C.blsSecretKey) {
	return (*C.blsSecretKey)(unsafe.Pointer(&sec.v[0]))
}

func (sec *SecretKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsSecretKeyGetStr(sec.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (sec *SecretKey) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsSecretKeySetStr(sec.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (sec *SecretKey) SetArray(v []uint64) error {
	if len(v) != 4 {
		return fmt.Errorf("bad size", len(v))
	}
	C.blsSecretKeySetArray(sec.getPointer(), (*C.uint64_t)(unsafe.Pointer(&v[0])))
	return nil
}

func (sec *SecretKey) Init() {
	C.blsSecretKeyInit(sec.getPointer())
}

func (sec *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(sec.getPointer(), rhs.getPointer())
}

func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i].Init()
	}
	return msk
}

func GetMasterPublicKey(msk []SecretKey) (mpk []PublicKey) {
	n := len(msk)
	mpk = make([]PublicKey, n)
	for i := 0; i < n; i++ {
		mpk[i] = *msk[i].GetPublicKey()
	}
	return mpk
}

func makeSecretKeyPointerArray(v []SecretKey) (pv []*C.blsSecretKey) {
	n := len(v)
	pv = make([]*C.blsSecretKey, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].getPointer()
	}
	return pv
}
func makePublicKeyPointerArray(v []PublicKey) (pv []*C.blsPublicKey) {
	n := len(v)
	pv = make([]*C.blsPublicKey, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].getPointer()
	}
	return pv
}
func makeSignPointerArray(v []Sign) (pv []*C.blsSign) {
	n := len(v)
	pv = make([]*C.blsSign, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].getPointer()
	}
	return pv
}
func makeIdPointerArray(v []Id) (pv []*C.blsId) {
	n := len(v)
	pv = make([]*C.blsId, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].getPointer()
	}
	return pv
}
func (sec *SecretKey) Set(msk []SecretKey, id *Id) {
	C.blsSecretKeySet(sec.getPointer(), msk[0].getPointer(), C.size_t(len(msk)), id.getPointer())
}

func (sec *SecretKey) Recover(secVec []SecretKey, idVec []Id) {
	C.blsSecretKeyRecover(sec.getPointer(), secVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(secVec)))
}

func (sec *SecretKey) GetPop() (sign *Sign) {
	sign = new(Sign)
	C.blsSecretKeyGetPop(sec.getPointer(), sign.getPointer())
	return sign
}

type PublicKey struct {
	v [4 * 2 * 3]C.uint64_t
}

func (pub *PublicKey) getPointer() (p *C.blsPublicKey) {
	return (*C.blsPublicKey)(unsafe.Pointer(&pub.v[0]))
}

func (pub *PublicKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsPublicKeyGetStr(pub.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (pub *PublicKey) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsPublicKeySetStr(pub.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (pub *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(pub.getPointer(), rhs.getPointer())
}
func (pub *PublicKey) Set(msk []PublicKey, id *Id) {
	C.blsPublicKeySet(pub.getPointer(), msk[0].getPointer(), C.size_t(len(msk)), id.getPointer())
}

func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []Id) {
	C.blsPublicKeyRecover(pub.getPointer(), pubVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(pubVec)))
}

type Sign struct {
	v [4 * 3]C.uint64_t
}

func (sign *Sign) getPointer() (p *C.blsSign) {
	return (*C.blsSign)(unsafe.Pointer(&sign.v[0]))
}

func (sign *Sign) String() string {
	buf := make([]byte, 1024)
	n := C.blsSignGetStr(sign.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (sign *Sign) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsSignSetStr(sign.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = new(PublicKey)
	C.blsSecretKeyGetPublicKey(sec.getPointer(), pub.getPointer())
	return pub
}

func (sec *SecretKey) Sign(m string) (sign *Sign) {
	sign = new(Sign)
	buf := []byte(m)
	C.blsSecretKeySign(sec.getPointer(), sign.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return sign
}

func (sign *Sign) Add(rhs *Sign) {
	C.blsSignAdd(sign.getPointer(), rhs.getPointer())
}
func (sign *Sign) Recover(signVec []Sign, idVec []Id) {
	C.blsSignRecover(sign.getPointer(), signVec[0].getPointer(), idVec[0].getPointer(), C.size_t(len(signVec)))
}

func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	buf := []byte(m)
	return C.blsSignVerify(sign.getPointer(), pub.getPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) == 1
}

func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsSignVerifyPop(sign.getPointer(), pub.getPointer()) == 1
}
