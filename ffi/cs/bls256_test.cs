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
			Console.WriteLine("id={0}", id.GetStr(10));
			Console.WriteLine("id={0}", id.GetStr(16));
		}
		static void Main(string[] args)
		{
			try {
				Init();
				TestId();
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
