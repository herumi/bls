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
		static void Main(string[] args)
		{
			try {
				Init();
				TestId();
				TestSecretKey();
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
