using System;

namespace mcl
{
    using static BLS;
    class BLSTest
    {
        static int err = 0;
        static void assert(string msg, bool b) {
            if (b) return;
            Console.WriteLine("ERR {0}", msg);
            err++;
        }
        public static byte[] FromHexStr(string s)
        {
            if (s.Length % 2 == 1) {
                throw new ArgumentException("s.Length is odd." + s.Length);
            }
            int n = s.Length / 2;
            var buf = new byte[n];
            for (int i = 0; i < n; i++) {
                buf[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            }
            return buf;
        }
        static void TestId() {
            Console.WriteLine("TestId");
            Id id1;
            id1.SetDecStr("255");
            assert("GetStr(10)", id1.GetDecStr() == "255");
            assert("GetStr(16)", id1.GetHexStr() == "ff");
            Id id2;
            id2.SetInt(255);
            assert("IsEqual", id1.IsEqual(id2));
        }
        static void TestSecretKey() {
            Console.WriteLine("TestSecretKey");
            SecretKey sec;
            sec.SetHexStr("ff");
            assert("GetHexStr()", sec.GetHexStr() == "ff");
            {
                SecretKey sec2;
                sec.SetHexStr("321");
                sec2.SetHexStr("4000");
                sec.Add(sec2);
                assert("sec.Add", sec.GetHexStr() == "4321");
                sec.Sub(sec2);
                assert("sec.Sub", sec.GetHexStr() == "321");
                sec.SetByCSPRNG();
                Console.WriteLine("sec.SetByCSPRNG={0}", sec.GetHexStr());
                sec2 = sec;
                sec.Neg();
                Console.WriteLine("sec.Neg={0}", sec.GetHexStr());
                sec.Add(sec2);
                assert("sec.Add2", sec.GetHexStr() == "0");
                assert("sec.zero", sec.IsZero());
            }
            {
                SecretKey sec2;
                byte[] buf = sec.Serialize();
                sec2.Deserialize(buf);
                assert("serialize", sec2.IsEqual(sec));
            }
            {
                SecretKey sec2;
                sec.SetHexStr("0x11");
                sec2.SetHexStr("0x23");
                sec.Mul(sec2);
                assert("mul", sec.GetHexStr() == "253");
            }
        }
        static void TestPublicKey() {
            Console.WriteLine("TestPublicKey");
            SecretKey sec;
            sec.SetByCSPRNG();
            PublicKey pub = sec.GetPublicKey();
            string s = pub.GetHexStr();
            Console.WriteLine("pub={0}", s);
            {
                PublicKey pub2;
                pub2.SetStr(s);
                assert("pub.SetStr", pub.IsEqual(pub2));
            }
            {
                PublicKey pub2;
                byte[] buf = pub.Serialize();
                pub2.Deserialize(buf);
                assert("serialize", pub2.IsEqual(pub));
            }
            {
                PublicKey pub2 = pub;
                pub.Neg();
                pub.Add(pub2);
                assert("pub is zero", pub.IsZero());
            }
            {
                PublicKey pub2 = pub;
                for (int i = 0; i < 5; i++) {
                    pub2.Add(pub);
                }
                PublicKey pub3 = pub;
                SecretKey t;
                t.SetHexStr("5");
                pub3.Mul(t);
                assert("pub mul", pub2.IsEqual(pub3));
            }
        }
        static void TestSign() {
            Console.WriteLine("TestSign");
            SecretKey sec;
            sec.SetByCSPRNG();
            PublicKey pub = sec.GetPublicKey();
            string m = "abc";
            Signature sig = sec.Sign(m);
            Console.WriteLine("sig={0}", sig.GetHexStr());
            assert("verify", pub.Verify(sig, m));
            assert("not verify", !pub.Verify(sig, m + "a"));
            {
                Signature sig2;
                byte[] buf = sig.Serialize();
                sig2.Deserialize(buf);
                assert("serialize", sig2.IsEqual(sig));
            }
            {
                Signature sig2 = sig;
                sig.Neg();
                sig.Add(sig2);
                assert("sig is zero", sig.IsZero());
            }
            {
                Signature sig2 = sig;
                for (int i = 0; i < 5; i++) {
                    sig2.Add(sig);
                }
                Signature sig3 = sig;
                SecretKey t;
                t.SetHexStr("5");
                sig3.Mul(t);
                assert("sig mul", sig2.IsEqual(sig3));
            }
        }
        static void TestSharing() {
            Console.WriteLine("TestSharing");
            int k = 5;
            SecretKey[] msk = new SecretKey[k];
            PublicKey[] mpk = new PublicKey[k];
            // make master secretkey
            for (int i = 0; i < k; i++) {
                msk[i].SetByCSPRNG();
                mpk[i] = msk[i].GetPublicKey();
            }
            int n = 30;
            Id[] ids = new Id[n];
            SecretKey[] secs = new SecretKey[n];
            PublicKey[] pubs = new PublicKey[n];
            for (int i = 0; i < n; i++) {
                ids[i].SetInt(i * i + 123);
                secs[i] = ShareSecretKey(msk, ids[i]);
                pubs[i] = SharePublicKey(mpk, ids[i]);
                assert("share publicKey", secs[i].GetPublicKey().IsEqual(pubs[i]));
            }
            string m = "doremi";
            for (int i = 0; i < n; i++) {
                Signature Signature = secs[i].Sign(m);
                assert("Signature.Verify", pubs[i].Verify(Signature, m));
            }
            {
                int[] idxTbl = { 0, 2, 5, 8, 10 };
                assert("idxTbl.Length=k", idxTbl.Length == k);
                Id[] subIds = new Id[k];
                SecretKey[] subSecs = new SecretKey[k];
                PublicKey[] subPubs = new PublicKey[k];
                Signature[] subSigns = new Signature[k];
                for (int i = 0; i < k; i++) {
                    int idx = idxTbl[i];
                    subIds[i] = ids[idx];
                    subSecs[i] = secs[idx];
                    subPubs[i] = pubs[idx];
                    subSigns[i] = secs[idx].Sign(m);
                }
                SecretKey sec = RecoverSecretKey(subSecs, subIds);
                PublicKey pub = RecoverPublicKey(subPubs, subIds);
                assert("check pub", pub.IsEqual(sec.GetPublicKey()));
                Signature Signature = RecoverSign(subSigns, subIds);
                assert("Signature.verify", pub.Verify(Signature, m));
            }
        }
        static void TestAggregate() {
            Console.WriteLine("TestAggregate");
            const int n = 10;
            const string m = "abc";
            SecretKey[] secVec = new SecretKey[n];
            PublicKey[] pubVec = new PublicKey[n];
            Signature[] popVec = new Signature[n];
            Signature[] sigVec = new Signature[n];
            for (int i = 0; i < n; i++) {
                secVec[i].SetByCSPRNG();
                pubVec[i] = secVec[i].GetPublicKey();
                popVec[i] = secVec[i].GetPop();
                sigVec[i] = secVec[i].Sign(m);
            }
            SecretKey secAgg;
            PublicKey pubAgg;
            Signature sigAgg;
            for (int i = 0; i < n; i++) {
                secAgg.Add(secVec[i]);
                assert("verify pop", pubVec[i].VerifyPop(popVec[i]));
                pubAgg.Add(pubVec[i]);
                sigAgg.Add(sigVec[i]);
            }
            assert("aggregate sec", secAgg.Sign(m).IsEqual(sigAgg));
            assert("aggregate", pubAgg.Verify(sigAgg, m));
            // sub
            secAgg = secVec[0];
            secAgg.Add(secVec[1]);
            secAgg.Sub(secVec[1]);
            assert("SecretKey.Sub", secAgg.IsEqual(secVec[0]));
            pubAgg = pubVec[0];
            pubAgg.Add(pubVec[1]);
            pubAgg.Sub(pubVec[1]);
            assert("PubretKey.Sub", pubAgg.IsEqual(pubVec[0]));
            sigAgg = sigVec[0];
            sigAgg.Add(sigVec[1]);
            sigAgg.Sub(sigVec[1]);
            assert("Signature.Sub", sigAgg.IsEqual(sigVec[0]));
        }
        static void TestMulVec()
        {
            Console.WriteLine("TestMulVec");
            int n = 10;
            const string m = "abc";
            SecretKey[] secVec = new SecretKey[n];
            PublicKey[] pubVec = new PublicKey[n];
            Signature[] sigVec = new Signature[n];
            SecretKey[] frVec = new SecretKey[n];

            for (int i = 0; i < n; i++) {
                secVec[i].SetByCSPRNG();
                pubVec[i] = secVec[i].GetPublicKey();
                sigVec[i] = secVec[i].Sign(m);
                frVec[i].SetByCSPRNG();
            }
            PublicKey aggPub = MulVec(pubVec, frVec);
            Signature aggSig = MulVec(sigVec, frVec);
            assert("mulVec", aggPub.Verify(aggSig, m));
        }
        static void TestFastAggregateVerify()
        {
            Console.WriteLine("TestFastAggregateVerify");
            var tbl = new[] {
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msg = "abababababababababababababababababababababababababababababababab",
                    sig = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff",
                    expected = false,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                    },
                    msg = "0000000000000000000000000000000000000000000000000000000000000000",
                    sig = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
                    expected = true,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                    },
                    msg = "5656565656565656565656565656565656565656565656565656565656565656",
                    sig = "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1",
                    expected = true,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msg = "abababababababababababababababababababababababababababababababab",
                    sig = "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
                    expected = true,
                },
            };
            foreach (var v in tbl) {
                int n = v.pubVec.Length;
                PublicKey[] pubVec = new PublicKey[n];
                bool result = false;
                try {
                    for (int i = 0; i < n; i++) {
                        pubVec[i].Deserialize(FromHexStr(v.pubVec[i]));
                    }
                    var msg = FromHexStr(v.msg);
                    Signature sig = new Signature();
                    sig.Deserialize(FromHexStr(v.sig));
                    result = FastAggregateVerify(sig, pubVec, msg);
                }
                catch (Exception) {
                    // pass through
                }
                assert("FastAggregateVerify", result == v.expected);
            }
        }
        static void TestAggregateVerify()
        {
            Console.WriteLine("TestAggregateVerify");
            var tbl = new[] {
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                        "abababababababababababababababababababababababababababababababab",
                    },
                    sig = "9104e74bffffffff",
                    expected = false,
                },
                new {
                    pubVec = new[] {
                        "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
                        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
                        "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
                    },
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "5656565656565656565656565656565656565656565656565656565656565656",
                        "abababababababababababababababababababababababababababababababab",
                    },
                    sig = "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244",
                    expected = true,
                },
            };
            foreach (var v in tbl) {
                int n = v.pubVec.Length;
                PublicKey[] pubVec = new PublicKey[n];
                bool result = false;
                try {
                    for (int i = 0; i < n; i++) {
                        pubVec[i].Deserialize(FromHexStr(v.pubVec[i]));
                    }
                    Msg[] msgVec = new Msg[n];
                    for (int i = 0; i < n; i++) {
                        msgVec[i].Set(FromHexStr(v.msgVec[i]));
                    }
                    Signature sig = new Signature();
                    sig.Deserialize(FromHexStr(v.sig));
                    result = AggregateVerify(sig, pubVec, msgVec);
                } catch (Exception) {
                    // pass through
                }
                assert("AggregateVerify", result == v.expected);
            }
        }
        static void TestAreAllMsgDifferent()
        {
            Console.WriteLine("TestAreAllMsgDifferent");
            var tbl = new[] {
                new {
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    },
                    expected = true,
                },
                new {
                    msgVec = new[] {
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    expected = false,
                },
            };
            foreach (var t in tbl) {
                int n = t.msgVec.Length;
                var msgVec = new Msg[n];
                for (int i = 0; i < n; i++) {
                    msgVec[i].Set(FromHexStr(t.msgVec[i]));
                }
                assert("verify", AreAllMsgDifferent(msgVec) == t.expected);
            }
        }
        static void Main(string[] args) {
            try {
                int[] curveTypeTbl = { BN254, BLS12_381 };
                foreach (int curveType in curveTypeTbl) {
                    if (isETH && curveType != BLS12_381) {
                        continue;
                    }
                    Console.WriteLine("curveType={0}", curveType);
                    if (!isETH) {
                        Init(curveType);
                    }
                    TestId();
                    TestSecretKey();
                    TestPublicKey();
                    TestSign();
                    TestSharing();
                    TestAggregate();
                    TestMulVec();
                    TestAreAllMsgDifferent();
                    if (isETH) {
                        TestFastAggregateVerify();
                        TestAggregateVerify();
                    }
                    if (err == 0) {
                        Console.WriteLine("all tests succeed");
                    } else {
                        Console.WriteLine("err={0}", err);
                    }
                }
            } catch (Exception e) {
                Console.WriteLine("ERR={0}", e);
            }
        }
    }
}
