package bls

/*
#cgo CFLAGS:-I../../include
#cgo LDFLAGS:-lbls -lbls_if -lmcl -lgmp -lgmpxx -L../lib -L../../lib -L../../../mcl/lib -L../../mcl/lib  -lstdc++ -lcrypto
#include "bls_if.h"
*/
import "C"
import "fmt"
import "runtime"
import "unsafe"

func Init() {
	C.blsInit()
}

type Id struct {
	self *C.blsId
}

func destroyBlsId(p *Id) {
	C.blsIdDestroy(p.self)
}

func NewId() *Id {
	p := new(Id)
	p.self = C.blsIdCreate()
	runtime.SetFinalizer(p, destroyBlsId)
	return p
}

func (id *Id) String() string {
	buf := make([]byte, 1024)
	n := C.blsIdGetStr(id.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (id *Id) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsIdSetStr(id.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (id *Id) Set(v []uint64) error {
	if len(v) != 4 {
		return fmt.Errorf("bad size", len(v))
	}
	C.blsIdSet(id.self, (*C.uint64_t)(unsafe.Pointer(&v[0])))
	return nil
}

type SecretKey struct {
	self *C.blsSecretKey
}

func destroyBlsSecretKey(p *SecretKey) {
	C.blsSecretKeyDestroy(p.self)
}

func NewSecretKey() *SecretKey {
	p := new(SecretKey)
	p.self = C.blsSecretKeyCreate()
	runtime.SetFinalizer(p, destroyBlsSecretKey)
	return p
}

func (sec *SecretKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsSecretKeyGetStr(sec.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (sec *SecretKey) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsSecretKeySetStr(sec.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (sec *SecretKey) SetArray(v []uint64) error {
	if len(v) != 4 {
		return fmt.Errorf("bad size", len(v))
	}
	C.blsSecretKeySetArray(sec.self, (*C.uint64_t)(unsafe.Pointer(&v[0])))
	return nil
}

func (sec *SecretKey) Init() {
	C.blsSecretKeyInit(sec.self)
}

func (sec *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(sec.self, rhs.self);
}

func (sec *SecretKey) GetMasterSecretKey(k int) (msk []SecretKey) {
	msk = make([]SecretKey, k)
	msk[0] = *sec
	for i := 1; i < k; i++ {
		msk[i] = *NewSecretKey()
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
		pv[i] = v[i].self
	}
	return pv
}
func makePublicKeyPointerArray(v []PublicKey) (pv []*C.blsPublicKey) {
	n := len(v)
	pv = make([]*C.blsPublicKey, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].self
	}
	return pv
}
func makeSignPointerArray(v []Sign) (pv []*C.blsSign) {
	n := len(v)
	pv = make([]*C.blsSign, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].self
	}
	return pv
}
func makeIdPointerArray(v []Id) (pv []*C.blsId) {
	n := len(v)
	pv = make([]*C.blsId, n)
	for i := 0; i < n; i++ {
		pv[i] = v[i].self
	}
	return pv
}
func (sec *SecretKey) Set(msk []SecretKey, id *Id) {
	v := makeSecretKeyPointerArray(msk)
	C.blsSecretKeySet(sec.self, (**C.blsSecretKey)(unsafe.Pointer(&v[0])), C.size_t(len(msk)), id.self)
}

func (sec *SecretKey) Recover(secVec []SecretKey, idVec []Id) {
	sv := makeSecretKeyPointerArray(secVec)
	iv := makeIdPointerArray(idVec)
	C.blsSecretKeyRecover(sec.self, (**C.blsSecretKey)(unsafe.Pointer(&sv[0])), (**C.blsId)(unsafe.Pointer(&iv[0])), C.size_t(len(secVec)))
}

func (sec *SecretKey) GetPop() (sign *Sign) {
	sign = NewSign()
	C.blsSecretKeyGetPop(sec.self, sign.self)
	return sign
}

type PublicKey struct {
	self *C.blsPublicKey
}

func destroyBlsPublicKey(p *PublicKey) {
	C.blsPublicKeyDestroy(p.self)
}

func NewPublicKey() *PublicKey {
	p := new(PublicKey)
	p.self = C.blsPublicKeyCreate()
	runtime.SetFinalizer(p, destroyBlsPublicKey)
	return p
}

func (pub *PublicKey) String() string {
	buf := make([]byte, 1024)
	n := C.blsPublicKeyGetStr(pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (pub *PublicKey) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsPublicKeySetStr(pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (pub *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(pub.self, rhs.self);
}
func (sec *PublicKey) Set(msk []PublicKey, id *Id) {
	v := makePublicKeyPointerArray(msk)
	C.blsPublicKeySet(sec.self, (**C.blsPublicKey)(unsafe.Pointer(&v[0])), C.size_t(len(msk)), id.self)
}

func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []Id) {
	sv := makePublicKeyPointerArray(pubVec)
	iv := makeIdPointerArray(idVec)
	C.blsPublicKeyRecover(pub.self, (**C.blsPublicKey)(unsafe.Pointer(&sv[0])), (**C.blsId)(unsafe.Pointer(&iv[0])), C.size_t(len(pubVec)))
}

type Sign struct {
	self *C.blsSign
}

func destroyBlsSign(p *Sign) {
	C.blsSignDestroy(p.self)
}

func NewSign() *Sign {
	p := new(Sign)
	p.self = C.blsSignCreate()
	runtime.SetFinalizer(p, destroyBlsSign)
	return p
}

func (sign *Sign) String() string {
	buf := make([]byte, 1024)
	n := C.blsSignGetStr(sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

func (sign *Sign) SetStr(s string) error {
	buf := []byte(s)
	err := C.blsSignSetStr(sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if err > 0 {
		return fmt.Errorf("bad string:%s", s)
	}
	return nil
}

func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	pub = NewPublicKey()
	C.blsSecretKeyGetPublicKey(sec.self, pub.self)
	return pub
}

func (sec *SecretKey) Sign(m string) (sign *Sign) {
	sign = NewSign()
	buf := []byte(m)
	C.blsSecretKeySign(sec.self, sign.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return sign
}

func (sign *Sign) Add(rhs *Sign) {
	C.blsSignAdd(sign.self, rhs.self);
}
func (sign *Sign) Recover(signVec []Sign, idVec []Id) {
	sv := makeSignPointerArray(signVec)
	iv := makeIdPointerArray(idVec)
	C.blsSignRecover(sign.self, (**C.blsSign)(unsafe.Pointer(&sv[0])), (**C.blsId)(unsafe.Pointer(&iv[0])), C.size_t(len(signVec)))
}

func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	buf := []byte(m)
	return C.blsSignVerify(sign.self, pub.self, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) == 1
}

func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsSignVerifyPop(sign.self, pub.self) == 1;
}
