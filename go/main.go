package main

import "fmt"
import "./blscgo"

//import "runtime"
//import "time"

var unitN = 0

func verifyTrue(b bool) {
	if !b {
		fmt.Println("ERR")
	}
}
func testRecoverSecretKey() {
	fmt.Println("testRecoverSecretKey")
	k := 3000
	var sec blscgo.SecretKey
	sec.Init()
	fmt.Println("sec =", sec)

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
	fmt.Println("sec2=", sec2)
}

func testSign() {
	m := "testSign"
	fmt.Println(m)

	var sec0 blscgo.SecretKey
	sec0.Init()
	pub0 := sec0.GetPublicKey()
	s0 := sec0.Sign(m)
	verifyTrue(s0.Verify(pub0, m))

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
		fmt.Printf("idVec[%d]=%s\n", i, idVec[i].String())

		secVec[i].Set(msk, &idVec[i])

		pubVec[i].Set(mpk, &idVec[i])
		fmt.Printf("pubVec[%d]=%s\n", i, pubVec[i].String())

		verifyTrue(pubVec[i].String() == secVec[i].GetPublicKey().String())

		signVec[i] = *secVec[i].Sign(m)
		verifyTrue(signVec[i].Verify(&pubVec[i], m))
	}
	var sec1 blscgo.SecretKey
	sec1.Recover(secVec, idVec)
	verifyTrue(sec0.String() == sec1.String())
	var pub1 blscgo.PublicKey
	pub1.Recover(pubVec, idVec)
	verifyTrue(pub0.String() == pub1.String())
	var s1 blscgo.Sign
	s1.Recover(signVec, idVec)
	verifyTrue(s0.String() == s1.String())
}

func testAdd() {
	fmt.Println("testAdd")
	var sec1 blscgo.SecretKey
	var sec2 blscgo.SecretKey
	sec1.Init()
	sec2.Init()

	pub1 := sec1.GetPublicKey()
	pub2 := sec2.GetPublicKey()

	m := "test test"
	sign1 := sec1.Sign(m)
	sign2 := sec2.Sign(m)

	fmt.Println("sign1    :", sign1)
	sign1.Add(sign2)
	fmt.Println("sign1 add:", sign1)
	pub1.Add(pub2)
	verifyTrue(sign1.Verify(pub1, m))
}

func testPop() {
	fmt.Println("testPop")
	var sec blscgo.SecretKey
	sec.Init()
	pop := sec.GetPop()
	verifyTrue(pop.VerifyPop(sec.GetPublicKey()))
	sec.Init()
	verifyTrue(!pop.VerifyPop(sec.GetPublicKey()))
}
func test(cp int) {
	fmt.Println("init")
	blscgo.Init(cp)
	unitN = blscgo.GetOpUnitSize()
	{
		var id blscgo.ID
		id.Set([]uint64{6, 5, 4, 3, 2, 1}[0:unitN])
		fmt.Println("id :", id)
		var id2 blscgo.ID
		id2.SetStr(id.String())
		fmt.Println("id2:", id2)
	}
	{
		var sec blscgo.SecretKey
		sec.SetArray([]uint64{1, 2, 3, 4, 5, 6}[0:unitN])
		fmt.Println("sec=", sec)
	}

	fmt.Println("create secret key")
	m := "this is a blscgo sample for go"
	var sec blscgo.SecretKey
	sec.Init()
	fmt.Println("sec:", sec)
	fmt.Println("create public key")
	pub := sec.GetPublicKey()
	fmt.Println("pub:", pub)
	sign := sec.Sign(m)
	fmt.Println("sign:", sign)
	verifyTrue(sign.Verify(pub, m))

	// How to make array of SecretKey
	{
		sec := make([]blscgo.SecretKey, 3)
		for i := 0; i < len(sec); i++ {
			sec[i].Init()
			fmt.Println("sec=", sec[i].String())
		}
	}
	testRecoverSecretKey()
	testAdd()
	testSign()
	testPop()
	fmt.Println("end of test")

	// put memory status
	/*
		runtime.GC()
		time.Sleep(2 * time.Second)
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		fmt.Println("mem=", mem)
	*/
}
func main() {
	fmt.Printf("GetMaxOpUnitSize() = %d\n", blscgo.GetMaxOpUnitSize())
	fmt.Println("CurveFp254BNb")
	test(blscgo.CurveFp254BNb)
	if blscgo.GetMaxOpUnitSize() == 6 {
		fmt.Println("CurveFp382_1")
		test(blscgo.CurveFp382_1)
		fmt.Println("CurveFp382_1")
		test(blscgo.CurveFp382_2)
	}
}
