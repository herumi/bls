package main

import "fmt"
import "./blscgo"
import "testing"

//import "runtime"
//import "time"

var unitN = 0

func verifyTrue(b bool) {
	if !b {
		fmt.Println("ERR")
	}
}
func testRecoverSecretKey(t *testing.T) {
	k := 3000
	var sec blscgo.SecretKey
	sec.Init()

	// make master secret key
	msk := sec.GetMasterSecretKey(k)

	n := k
	secVec := make([]blscgo.SecretKey, n)
	idVec := make([]blscgo.ID, n)
	for i := 0; i < n; i++ {
		idVec[i].Set([]uint64{1, 2, 3, uint64(i), 4, 5}[0:unitN])
		secVec[i].Set(msk, &idVec[i])
	}
	// recover sec2 from secVec and idVec
	var sec2 blscgo.SecretKey
	sec2.Recover(secVec, idVec)
	if sec.String() != sec2.String() {
		t.Fatal("sec err %s %s\n", sec, sec2)
	}
}

func testSign(t *testing.T) {
	m := "testSign"

	var sec0 blscgo.SecretKey
	sec0.Init()
	pub0 := sec0.GetPublicKey()
	s0 := sec0.Sign(m)
	if !s0.Verify(pub0, m) {
		t.Fatal("s0.Verify")
	}

	k := 3
	msk := sec0.GetMasterSecretKey(k)
	mpk := blscgo.GetMasterPublicKey(msk)

	idTbl := []uint64{3, 5, 193, 22, 15}
	n := len(idTbl)

	secVec := make([]blscgo.SecretKey, n)
	pubVec := make([]blscgo.PublicKey, n)
	signVec := make([]blscgo.Sign, n)
	idVec := make([]blscgo.ID, n)

	for i := 0; i < n; i++ {
		idVec[i].Set([]uint64{idTbl[i], 0, 0, 0, 0, 0}[0:unitN])

		secVec[i].Set(msk, &idVec[i])

		pubVec[i].Set(mpk, &idVec[i])

		if pubVec[i].String() != secVec[i].GetPublicKey().String() {
			t.Fatal("pubVec %d", i)
		}

		signVec[i] = *secVec[i].Sign(m)
		if !signVec[i].Verify(&pubVec[i], m) {
			t.Fatal("singVec %d", i)
		}
	}
	var sec1 blscgo.SecretKey
	sec1.Recover(secVec, idVec)
	if sec0.String() != sec1.String() {
		t.Fatal("sec0 sec1")
	}
	var pub1 blscgo.PublicKey
	pub1.Recover(pubVec, idVec)
	if pub0.String() != pub1.String() {
		t.Fatal("pub0 pub1")
	}
	var s1 blscgo.Sign
	s1.Recover(signVec, idVec)
	if s0.String() != s1.String() {
		t.Fatal("s0 s1")
	}
}

func testAdd(t *testing.T) {
	var sec1 blscgo.SecretKey
	var sec2 blscgo.SecretKey
	sec1.Init()
	sec2.Init()

	pub1 := sec1.GetPublicKey()
	pub2 := sec2.GetPublicKey()

	m := "test test"
	sign1 := sec1.Sign(m)
	sign2 := sec2.Sign(m)

	sign1.Add(sign2)
	pub1.Add(pub2)
	if !sign1.Verify(pub1, m) {
		t.Fatal("sign1.Verify")
	}
}

func testPop(t *testing.T) {
	var sec blscgo.SecretKey
	sec.Init()
	pop := sec.GetPop()
	if !pop.VerifyPop(sec.GetPublicKey()) {
		t.Fatal("pop.VerifyPop")
	}
	sec.Init()
	if pop.VerifyPop(sec.GetPublicKey()) {
		t.Fatal("pop.Verify another")
	}
}

func testData(t *testing.T) {
	var sec1, sec2 blscgo.SecretKey
	sec1.Init()
	s := sec1.GetData()
	sec2.SetData(s)
	if !sec1.IsSame(&sec2) {
		t.Fatal("SecretKey not same")
	}
	pub1 := sec1.GetPublicKey()
	s = pub1.GetData()
	var pub2 blscgo.PublicKey
	pub2.SetData(s)
	if !pub1.IsSame(&pub2) {
		t.Fatal("PublicKey not same")
	}
	m := "doremi"
	sign1 := sec1.Sign(m)
	s = sign1.GetData()
	var sign2 blscgo.Sign
	sign2.SetData(s)
	if !sign1.IsSame(&sign2) {
		t.Fatal("Sign not same")
	}
}

func test(t *testing.T, cp int) {
	blscgo.Init(cp)
	unitN = blscgo.GetOpUnitSize()
	{
		var id blscgo.ID
		id.Set([]uint64{6, 5, 4, 3, 2, 1}[0:unitN])
		var id2 blscgo.ID
		id2.SetStr(id.String())
		if id.String() != id2.String() {
			t.Fatal("id err %s %s", id, id2)
		}
	}
	{
		var sec blscgo.SecretKey
		sec.SetArray([]uint64{1, 2, 3, 4, 5, 6}[0:unitN])
	}

	fmt.Println("create secret key")
	m := "this is a blscgo sample for go"
	var sec blscgo.SecretKey
	sec.Init()
	pub := sec.GetPublicKey()
	sign := sec.Sign(m)
	if !sign.Verify(pub, m) {
		t.Fatal("sign.Verify")
	}

	// How to make array of SecretKey
	{
		sec := make([]blscgo.SecretKey, 3)
		for i := 0; i < len(sec); i++ {
			sec[i].Init()
		}
	}
	testRecoverSecretKey(t)
	testAdd(t)
	testSign(t)
	testPop(t)
	testData(t)

	// put memory status
	/*
		runtime.GC()
		time.Sleep(2 * time.Second)
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		fmt.Println("mem=", mem)
	*/
}

func TestMain(t *testing.T) {
	fmt.Printf("GetMaxOpUnitSize() = %d\n", blscgo.GetMaxOpUnitSize())
	fmt.Println("CurveFp254BNb")
	test(t, blscgo.CurveFp254BNb)
	if blscgo.GetMaxOpUnitSize() == 6 {
		fmt.Println("CurveFp382_1")
		test(t, blscgo.CurveFp382_1)
		fmt.Println("CurveFp382_1")
		test(t, blscgo.CurveFp382_2)
	}
}
