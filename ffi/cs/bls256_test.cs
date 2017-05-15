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
			id.SetStr("255", 10);
			assert("GetStr(10)", id.GetStr(10) == "255");
			assert("GetStr(16)", id.GetStr(16) == "ff");
			id.SetArray(new ulong[] { 1, 2, 3, 4 });
			assert("GetStr(16)", id.GetStr(16) == "4000000000000000300000000000000020000000000000001");
		}
		static void TestSecretKey()
		{
			Console.WriteLine("TestSecretKey");
			SecretKey sec = new SecretKey();
			sec.SetStr("255", 10);
			assert("GetStr(10)", sec.GetStr(10) == "255");
			assert("GetStr(16)", sec.GetStr(16) == "ff");
			sec.SetArray(new ulong[] { 1, 2, 3, 4 });
			assert("GetStr(16)", sec.GetStr(16) == "4000000000000000300000000000000020000000000000001");
			{
				SecretKey sec2 = new SecretKey();
				sec.SetStr("321", 10);
				sec2.SetStr("4000", 10);
				sec.Add(sec2);
				assert("sec.Add", sec.GetStr(10) == "4321");
				sec.Init();
				Console.WriteLine("sec.Init={0}", sec);
			}
		}
		static void TestPublicKey()
		{
			Console.WriteLine("TestPublicKey");
			SecretKey sec = new SecretKey();
			sec.Init();
			PublicKey pub = sec.GetPublicKey();
			String s = pub.ToString();
			Console.WriteLine("pub={0}", s);
			PublicKey pub2 = new PublicKey();
			pub2.SetStr(s);
			assert("pub.SetStr", pub.IsSame(pub2));
		}
		static void TestSign()
		{
			Console.WriteLine("TestSign");
			SecretKey sec = new SecretKey();
			sec.Init();
			PublicKey pub = sec.GetPublicKey();
			String m = "abc";
			Sign s = sec.Sign(m);
			assert("verify", s.Verify(pub, m));
			assert("not verify", !s.Verify(pub, m + "a"));
		}
		static void TestSharing()
		{
			Console.WriteLine("TestSharing");
			int k = 5;
			SecretKey[] msk = new SecretKey[k];
			PublicKey[] mpk = new PublicKey[k];
			// make master secretkey
			for (int i = 0; i < k; i++) {
				msk[i].Init();
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
				assert("share publicKey", secs[i].GetPublicKey().IsSame(pubs[i]));
			}
			string m = "doremi";
			for (int i = 0; i < n; i++) {
				Sign sign = secs[i].Sign(m);
				assert("sign.Verify", sign.Verify(pubs[i], m));
			}
			{
				int[] idxTbl = { 0, 2, 5, 8, 10 };
				assert("idxTbl.Length=k", idxTbl.Length == k);
				Id[] subIds = new Id[k];
				SecretKey[] subSecs = new SecretKey[k];
				PublicKey[] subPubs = new PublicKey[k];
				Sign[] subSigns = new Sign[k];
				for (int i = 0; i < k; i++) {
					int idx = idxTbl[i];
					subIds[i] = ids[idx];
					subSecs[i] = secs[idx];
					subPubs[i] = pubs[idx];
					subSigns[i] = secs[idx].Sign(m);
				}
				SecretKey sec = RecoverSecretKey(subSecs, subIds);
				PublicKey pub = RecoverPublicKey(subPubs, subIds);
				assert("check pub", pub.IsSame(sec.GetPublicKey()));
				Sign sign = RecoverSign(subSigns, subIds);
				assert("sign.verify", sign.Verify(pub, m));
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
