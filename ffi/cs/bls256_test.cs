using System;

namespace mcl {
	using static BLS256;
	class BLS256Test {
		static int err = 0;
		static void assert(string msg, bool b)
		{
			if (b) return;
			Console.WriteLine("ERR {0}", msg);
			err++;
		}
		static void TestId()
		{
			Console.WriteLine("TestId");
			Id id = new Id();
			id.SetDecStr("255");
			assert("GetStr(10)", id.GetDecStr() == "255");
			assert("GetStr(16)", id.GetHexStr() == "ff");
		}
		static void TestSecretKey()
		{
			Console.WriteLine("TestSecretKey");
			SecretKey sec = new SecretKey();
			sec.SetHexStr("ff");
			assert("GetHexStr()", sec.GetHexStr() == "ff");
			{
				SecretKey sec2 = new SecretKey();
				sec.SetHexStr("321");
				sec2.SetHexStr("4000");
				sec.Add(sec2);
				assert("sec.Add", sec.GetHexStr() == "4321");
				sec.SetByCSPRNG();
				Console.WriteLine("sec.Init={0}", sec.GetHexStr());
			}
		}
		static void TestPublicKey()
		{
			Console.WriteLine("TestPublicKey");
			SecretKey sec = new SecretKey();
			sec.SetByCSPRNG();
			PublicKey pub = sec.GetPublicKey();
			String s = pub.GetHexStr();
			Console.WriteLine("pub={0}", s);
			PublicKey pub2 = new PublicKey();
			pub2.SetStr(s);
			assert("pub.SetStr", pub.IsEqual(pub2));
		}
		static void TestSign()
		{
			Console.WriteLine("TestSign");
			SecretKey sec = new SecretKey();
			sec.SetByCSPRNG();
			PublicKey pub = sec.GetPublicKey();
			String m = "abc";
			Signature sig = sec.Signature(m);
			assert("verify", pub.Verify(sig, m));
			assert("not verify", !pub.Verify(sig, m + "a"));
		}
		static void TestSharing()
		{
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
				Signature Signature = secs[i].Signature(m);
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
					subSigns[i] = secs[idx].Signature(m);
				}
				SecretKey sec = RecoverSecretKey(subSecs, subIds);
				PublicKey pub = RecoverPublicKey(subPubs, subIds);
				assert("check pub", pub.IsEqual(sec.GetPublicKey()));
				Signature Signature = RecoverSign(subSigns, subIds);
				assert("Signature.verify", pub.Verify(Signature, m));
			}
		}
		static void Main(string[] args)
		{
			try {
				Init();
				TestId();
				TestSecretKey();
				TestPublicKey();
				TestSign();
				TestSharing();
				if (err == 0) {
					Console.WriteLine("all tests succeed");
				} else {
					Console.WriteLine("err={0}", err);
				}
			} catch (Exception e) {
				Console.WriteLine("ERR={0}", e);
			}
		}
	}
}
