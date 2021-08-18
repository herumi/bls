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
	public static String byteToHexStr(byte[] buf) {
		StringBuilder sb = new StringBuilder();
		for (byte b : buf) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
	public static byte[] hexStrToByte(String hex) {
		int n = hex.length();
		if ((n % 2) != 0) throw new IllegalArgumentException("hexStrToByte odd length");
		n /= 2;
		byte[] buf = new byte[n];
		for (int i = 0; i < n; i++) {
			int H = Character.digit(hex.charAt(i * 2 + 0), 16);
			int L = Character.digit(hex.charAt(i * 2 + 1), 16);
			buf[i] = (byte)(H * 16 + L);
		}
		return buf;
	}
	public static void printHex(String msg, byte[] buf) {
		System.out.print(msg + " " + byteToHexStr(buf));
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
		x.setHashOf(new byte[]{1, 2, 3});
		System.out.println("hashOf=" + x.toString(16));
	}
	public static void testPublicKey() {
		PublicKey x = new PublicKey();
		PublicKey y = new PublicKey();
	}
	public static void testSign() {
		SecretKey sec = new SecretKey();
		sec.setByCSPRNG();
		PublicKey pub = sec.getPublicKey();
		byte[] m = new byte[]{1, 2, 3, 4, 5};
		byte[] m2 = new byte[]{1, 2, 3, 4, 5, 6};
		Signature sig = sec.sign(m);
		printHex("sec", sec.serialize());
		printHex("pub", pub.serialize());
		printHex("sig", sig.serialize());
		assertBool("verify", sig.verify(pub, m));
		assertBool("!verify", !sig.verify(pub, m2));
	}
	public static void testShare() {
		int k = 3; // fix
		int n = 5;
		byte[] msg = new byte[]{3, 2, 4, 2, 5, 3, 4};
		SecretKeyVec msk = new SecretKeyVec();
		PublicKeyVec mpk = new PublicKeyVec();

		// setup msk (master secret key) and mpk (master public key)
		for (int i = 0; i < k; i++) {
			SecretKey sec = new SecretKey();
			sec.setByCSPRNG();
			msk.add(sec);
			PublicKey pub = sec.getPublicKey();
			mpk.add(pub);
		}
		// orgSig is signed by secret key
		Signature orgSig = msk.get(0).sign(msg);
		assertBool("verify", orgSig.verify(mpk.get(0), msg));
		// share
		SecretKeyVec ids = new SecretKeyVec();
		SecretKeyVec secVec = new SecretKeyVec();
		PublicKeyVec pubVec = new PublicKeyVec();
		SignatureVec sigVec = new SignatureVec();
		secVec.reserve(n);
		pubVec.reserve(n);
		sigVec.reserve(n);
		for (int i = 0; i < n; i++) {
			SecretKey id = new SecretKey();
			id.setByCSPRNG();
			ids.add(id);
			SecretKey sec = Bls.share(msk, ids.get(i));
			secVec.add(sec);
			PublicKey pub = Bls.share(mpk, ids.get(i));
			pubVec.add(pub);
			Signature sig = sec.sign(msg);
			sigVec.add(sig);
		}
		// recover
		SecretKeyVec idVec2 = new SecretKeyVec(k, new SecretKey());
		PublicKeyVec pubVec2 = new PublicKeyVec(k, new PublicKey());
		SignatureVec sigVec2 = new SignatureVec(k, new Signature());
		for (int i0 = 0; i0 < n; i0++) {
			for (int i1 = i0 + 1; i1 < n; i1++) {
				for (int i2 = i1 + 1; i2 < n; i2++) {
					idVec2.set(0, ids.get(i0));
					idVec2.set(1, ids.get(i1));
					idVec2.set(2, ids.get(i2));
					pubVec2.set(0, pubVec.get(i0));
					pubVec2.set(1, pubVec.get(i1));
					pubVec2.set(2, pubVec.get(i2));
					sigVec2.set(0, sigVec.get(i0));
					sigVec2.set(1, sigVec.get(i1));
					sigVec2.set(2, sigVec.get(i2));
					PublicKey pub = Bls.recover(pubVec2, idVec2);
					Signature sig = Bls.recover(sigVec2, idVec2);
					assertBool("recover pub", pub.equals(mpk.get(0)));
					assertBool("recover sig", sig.equals(orgSig));
				}
			}
		}
	}
	public static void testAggregateSignature() {
		int n = 10;
		PublicKey aggPub = new PublicKey();
		PublicKeyVec pubVec = new PublicKeyVec();
		SignatureVec sigVec = new SignatureVec();
		byte[] msg = new byte[]{1, 2, 3, 5, 9};
		aggPub.clear();
		for (int i = 0; i < n; i++) {
			SecretKey sec = new SecretKey();
			sec.setByCSPRNG();
			PublicKey pub = sec.getPublicKey();
			Signature sig = sec.sign(msg);
			aggPub.add(pub);
			pubVec.add(pub);
			sigVec.add(sig);
		}
		Signature aggSig = Bls.aggregate(sigVec);
		assertBool("aggSig.verify", aggSig.verify(aggPub, msg));
		assertBool("fastAggregateVerify", aggSig.fastAggregateVerify(pubVec, msg));
	}
	public static void addVec(ByteArrayOutputStream os, PublicKeyVec pubVec, SignatureVec sigVec, int n, boolean isDiff) {
		for (int i = 0; i < n; i++) {
			byte[] msg = new byte[Bls.MSG_SIZE];
			if (isDiff) {
				msg[0] = (byte)i;
				msg[1] = (byte)(i + 2);
			} else {
				msg[0] = (byte)(i % 4);
			}
			try {
				os.write(msg);
			} catch (IOException e) {
				assertBool("os.write", false);
				return;
			}
			SecretKey sec = new SecretKey();
			sec.setByCSPRNG();
			pubVec.add(sec.getPublicKey());
			sigVec.add(sec.sign(msg));
		}
	}
	public static void testHex() {
		System.out.println("testHex");
		byte[] b = new byte[]{1, 2, 3, 4, 0x12, (byte)0xff };
		String s = byteToHexStr(b);
		assertEquals("byteToHexStr", s, "0102030412ff");
		byte[] b2 = hexStrToByte(s);
		assertBool("hexStrToByte", java.util.Arrays.equals(b2, b));
	}
	public static void testAggregateVerify() {
		System.out.println("testAggregateVerify");
		final int n = 10;
		for (int i = 0; i < 2; i++) {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			boolean isDiff = i == 0;
			PublicKeyVec pubVec = new PublicKeyVec();
			SignatureVec sigVec = new SignatureVec();
			addVec(os, pubVec, sigVec, n, isDiff);
			byte[] msgVec = os.toByteArray();
			Signature aggSig = Bls.aggregate(sigVec);
			assertBool("aggregateVerifyNoCheck", aggSig.aggregateVerifyNoCheck(pubVec, msgVec));
			if (isDiff) {
				assertBool("aggregateVerify", aggSig.aggregateVerify(pubVec, msgVec));
			} else {
				assertBool("!aggregateVerify", !aggSig.aggregateVerify(pubVec, msgVec));
			}
		}
	}
	public static void testCurve(int curveType, String name) {
		try {
			System.out.println("curve=" + name);
			Bls.init(curveType);
			testHex();
			testSecretKey();
			testPublicKey();
			testSign();
			testShare();
			testAggregateSignature();
			if (Bls.isDefinedBLS_ETH() && curveType == Bls.BLS12_381) {
				System.out.println("BLS ETH mode");
				testAggregateVerify();
				// setting for Harmony.ONE (make library with BLS_ETH=1)
				/*
					Bls.setETHserialization(false);
					Bls.setMapToMode(Bls.MAP_TO_MODE_ORIGINAL);
					PublicKey gen = new PublicKey();
					gen.setStr("1 17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");
					Bls.setGeneratorOfPublicKey(gen);
				*/
			}
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
