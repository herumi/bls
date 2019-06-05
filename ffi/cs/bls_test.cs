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
                sec.SetByCSPRNG();
                Console.WriteLine("sec.Init={0}", sec.GetHexStr());
            }
            {
                SecretKey sec2;
                byte[] buf = sec.Serialize();
                sec2.Deserialize(buf);
                assert("serialize", sec2.IsEqual(sec));
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
        }
        static void Main(string[] args) {
            try {
                int[] curveTypeTbl = { BN254, BLS12_381 };
                foreach (int curveType in curveTypeTbl) {
                    Console.WriteLine("curveType={0}", curveType);
                    Init(curveType);
                    TestId();
                    TestSecretKey();
                    TestPublicKey();
                    TestSign();
                    TestSharing();
                    TestAggregate();
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
