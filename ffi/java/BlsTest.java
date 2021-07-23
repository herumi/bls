import java.io.*;
import com.herumi.bls.*;

/*
	BlsTest
*/
public class BlsTest {
	static {
		String lib = "blsjava";
		String libName = System.mapLibraryName(lib);
		System.out.println("libName : " + libName);
		System.loadLibrary(lib);
	}
	public static int errN = 0;
	public static void assertEquals(String msg, String x, String y) {
		if (x.equals(y)) {
			System.out.println("OK : " + msg);
		} else {
			System.out.println("NG : " + msg + ", x = " + x + ", y = " + y);
			errN++;
		}
	}
	public static void assertBool(String msg, boolean b) {
		if (b) {
			System.out.println("OK : " + msg);
		} else {
			System.out.println("NG : " + msg);
			errN++;
		}
	}
	public static void testSecretKey() {
		SecretKey sec = new SecretKey(255);
		assertEquals("sec.dec", sec.toString(), "255");
		assertEquals("sec.hex", sec.toString(16), "ff");
		byte[] b = sec.serialize();
		{
			SecretKey sec2 = new SecretKey();
			sec2.deserialize(b);
			assertBool("sec.serialize", sec.equals(sec2));
		}
	}
	public static void testCurve(int curveType, String name) {
		try {
			System.out.println("curve=" + name);
			Bls.init(curveType);
			testSecretKey();
			if (errN == 0) {
				System.out.println("all test passed");
			} else {
				System.out.println("ERR=" + errN);
			}
		} catch (RuntimeException e) {
			System.out.println("unknown exception :" + e);
		}
	}
	public static void main(String argv[]) {
		testCurve(Bls.BN254, "BN254");
		testCurve(Bls.BLS12_381, "BLS12_381");
	}
}
