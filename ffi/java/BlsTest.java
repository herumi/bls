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
		SecretKey x = new SecretKey(255);
		SecretKey y = new SecretKey();
		assertEquals("x.dec", x.toString(), "255");
		assertEquals("x.hex", x.toString(16), "ff");
		assertBool("x.!isZero", !x.isZero());
		x.clear();
		assertBool("x.isZero", x.isZero());
		x.setByCSPRNG();
		System.out.println("x.setByCSPRNG()=" + x.toString(16));
		byte[] b = x.serialize();
		{
			y.deserialize(b);
			assertBool("x.serialize", x.equals(y));
		}
		x.setInt(5);
		y.setInt(10);
		x.add(y);
		assertEquals("x.add", x.toString(), "15");
		x.setInt(13);
		y.setInt(7);
		x.sub(y);
		assertEquals("x.sub", x.toString(), "6");
		x.setInt(-9);
		x.neg();
		y.setInt(7);
		x.add(y);
		assertEquals("x.neg", x.toString(), "16");
		x.setInt(9);
		y.setInt(7);
		x.mul(y);
		assertEquals("x.mul", x.toString(), "63");
	}
	public static void testPublicKey() {
		PublicKey x = new PublicKey();
		PublicKey y = new PublicKey();
	}
	public static void testSign() {
		SecretKey sec = new SecretKey();
		sec.setByCSPRNG();
		PublicKey pub = new PublicKey();
		sec.getPublicKey(pub);
		byte[] m = new byte[]{1, 2, 3, 4, 5};
		byte[] m2 = new byte[]{1, 2, 3, 4, 5, 6};
		Signature sig = new Signature();
		sec.sign(sig, m);
		assertBool("verify", sig.verify(pub, m));
		assertBool("!verify", !sig.verify(pub, m2));
	}
	public static void testCurve(int curveType, String name) {
		try {
			System.out.println("curve=" + name);
			Bls.init(curveType);
			testSecretKey();
			testPublicKey();
			testSign();
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
