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
	public static void testHarmonyONE() {
		assertBool("requirements", Bls.isDefinedBLS_ETH());
		System.out.println("testHarmonyONE");
		// setting for Harmony.ONE (make library with BLS_ETH=1)
		Bls.init(Bls.BLS12_381);
		Bls.setETHserialization(false);
		Bls.setMapToMode(Bls.MAP_TO_MODE_ORIGINAL);
		PublicKey gen = new PublicKey();
		// the old generator
		gen.setStr("1 4f58f3d9ee829f9a853f80b0e32c2981be883a537f0c21ad4af17be22e6e9959915ec21b7f9d8cc4c7315f31f3600e5 1212110eb10dbc575bccc44dcd77400f38282c4728b5efac69c0b4c9011bd27b8ed608acd81f027039216a291ac636a8");
		Bls.setGeneratorOfPublicKey(gen);

		SecretKey sec = new SecretKey();
		sec.deserialize(new byte[] {
			-71, 10, 0, -19, -60, -25, -21, -3, 95, -35, 36, -32, 109, -4, 10, -34, 14, -59, 82, 107, -36, 29, -48, 123, -87, -66, 98, -75, -16, -58, 35, 98});
		Signature sig = new Signature();
		sec.signHash(sig, new byte[] {
-71, 10, 0, -19, -60, -25, -21, -3, 95, -35, 36, -32, 109, -4, 10, -34, 14, -59, 82, 107, -36, 29, -48, 123, -87, -66, 98, -75, -16, -58, 35, 98
		});
		assertBool("check sig", byteToHexStr(sig.serialize()).equals("2f4ff940216b2f13d75a231b988cd16ef22b45a4709df3461d9baeebfeaafeb54fad86ea7465212f35ceb0af6fe86b1828cf6de9099cefe233d97e0523ba6c0f5eecf4db71f7b1ae08cd098547946abbd0329fdac14d27102f2a1891e9188a19"));

		sec.deserialize(hexStrToByte("6a28f0bccfdd5e170c55090fa2ca5d99f5b2d3a8b45a94ff5c8ea3e77355c70a"));
		PublicKey pub = sec.getPublicKey();
		assertBool("check pub", byteToHexStr(pub.serialize()).equals("02d3fe69f048f400fe194b9ea90dc53321f5d26e231be5d3761dc70b770bddc49ade94f4f30869f02065f4c2b59e7a13"));
		String[] dataHex = new String[]{
"1100000000000000000000000000000000000000000000000000000000000000",
"291c4dec859dd0a03f72072e27455ebf4f0c892a1786bffcebd51ae462c06471311ad23594cea6273045d1552c22e7044c11bec8127fb8d483ce954f27f838831fa3c59e91627db4dda38289e5c1927ad3d76ae69f9bb9f70599f8e383beb40c",
"3b02d8816351241bf74b0039cd0b3f21c55aa5c42a37c63da526ddb02d85ebbc39bf559eded60281f5eb047e5055af0ae8f2c11d8173e81a0e57d7ced228a43a43803580fec4da469ed2933023576e85c1f7954bdce6d1b6d887d0d9cfb87e85",
"2100000000000000000000000000000000000000000000000000000000000000",
"9e932c1dcdf377dcce87a0e03cd4aa5b034edcb9402975f16bc06f4fcd6c477a7b5c99a6ee698c77339c9bdd0e50501086352259f0d2bab11a42283176bcb8161de5a3e69ec9752556248c37221cb2d4b50df15f99e74850414ae5e881e5f406",
"3415144be4cb4c614eb1be16e7176d09f7524d444a95689e73abdf0d26e7d0709110dccc288487d052c23973f3f5b00d939ef36c0a3aa634ca613f11a0147befbf6997304d93790128029f3fb17ca462927bfff8b3fa1dcb5c2c31879ba7f98b",
"3100000000000000000000000000000000000000000000000000000000000000",
"8acda2d07486d9ad62786475a8089104aa3797bc1d284bf3a5e945e56b953a33d6e7fcdfde311bbf9db4809df8568509142d52c51cd8e09f28e31f0546f4d2ed6fdab9b223ef35859a0e338d7216f155c4891e61a4c88731f54d8f9459267f05",
"ed2fd8670949de0e61e8b89a8e86b857e613a2d7f930a2b681bc9e272fc20ba27b1027e98be90d7f6d36873231dd9c151fa442488823c2c0d16bc3af67bf277e8240354acac8c9e6f968045b4379247ce155ca034cc775bc1629d2443bbc6f8a",
"4100000000000000000000000000000000000000000000000000000000000000",
"73f729f352ef5fa0d4738aeda37f73cd5f55acae990d6db059852339a0aa26c30c2b0c89ef0e7fa8a52e52aa0806a00f804436f2835bb73863f305655cd901f998db451f30609680ddba401b585900fcde777de61856fdc0dcae8aa1f5a21393",
"42aec61104f35aab537305d21f995ba52140a98959a2d45a1ab8569c992844459d9c4f523d0cd973dad28ba37d97b0019f83d66628760747c41250e7e0b297be63f7af1a71a906664d1562c5c0f842eecf5e3956ce09346aa7d553f96fcdc699",
"5100000000000000000000000000000000000000000000000000000000000000",
"7a5b371c1e5e2b5fdc354d80a55eb07d9260650ee1aef9d8a7ce743de7e2115d8cf973f2752d2707d2168d7fa7dd2608e672a2bee1888a37703209a5b4424e3bf7c47ea143d42651df222e5581bee5492dcc9a114423d2b6209ffd938b59fa95",
"14ab076128b1274026db048e5f6fc5a168ea7082528ec855e6bd55c3d51f0cbc81ef02bdbad4ad5cf21ec4b7a9172c139c7d9679662ed0948abf383ad82fc441c8c292c3bf8e502519dd1b620e43f17a9cf3b66c5cc475a8c3f9e75437e85c02",
"6100000000000000000000000000000000000000000000000000000000000000",
"15abc02bbb1dc52ebe5c663a2380420c207403a92e83192f3b4675e44ed98646fbbee6e3b358fd4226c2a85e1b3205116eb3cc96a4a803278f7a9249a498dcd83136dd6ba76a4a160d732e8168193187b18bbc155b06ecb999712fcaa9cd8411",
"188a88b02d2d4b48551d054fc0184b5941c16a56c98fa2e20a768865b83bd0f540c1f3bf26b96a7a98440720348ab2146210d2fa69246c77b301da415197c04a81a0fd27e8bcac3f64a8045c1aa0da2167b8efae787c32842f415d8bdb8a758e",
"7100000000000000000000000000000000000000000000000000000000000000",
"b81284c758886ab93d1c6961825bff8041acecfbe67476c7cd12d6a4568de66e03681e6287259def07ce622667e242194b9b032ca03be95f34e1f81691c50a09ba439e4208691a066ea3e681af0cc9cd2b0cee8514d8aaa243374369b70b6c12",
"a6280d638e3e29c4a6ae8289b9bcfbaa108d4aa1239a934565683c10b241a5c835c958faa921ae104b9d028c5f9bdd0b2f54e0fddf423e4f4985fc5c8bc04149e21e0013631e766f39c91b56192fa6de4b041ab957227659001b099598864d80",
"8100000000000000000000000000000000000000000000000000000000000000",
"ea0f2c482d4f14a735c6ac843a7a00c012fe2566ee6b3d0f644cfd68a5cbe98ff1daf7043f58fa82ba1990fe5a1a5115eb00db16411a9e37f649f8d7470d2447a81d539afff2f8e1f95a48f5ab319b425575b260298b7c4376a3984fecda058e",
"d74ef73299cd7963c7652ab2c73ff2488d39ee1dfa352d3e445980d1be5289cd0fd03e8c3d04e26fb37cc59981c8b41814f9d7b33150cb519f14045c20e1370383c538881fda039290cd6ca7f931caf5b666e7d6e218d2eea7164e932ed10418",
"9100000000000000000000000000000000000000000000000000000000000000",
"94af8904d7231687703023ab26a52db2cda8429f8f565eddc284e33c9231b5785d43ede7c9ebaae7e563bfaf9b77500fcc479bbcb6618c2f1de883d436d72a4dfdfe00f6ce19c082b4c172b460b601ffd4b4aa81e63f1753ab47f4d513b12504",
"8e0d5cdf460f1b14661cad69303ad714f16b44a3e8188e81bf254cdbba2d67e3e8545511c87171dbbee0023334495305e412aa6a3e9666a37b57f21a9e0acd70be67d29ec84f639c9a36bd382955489caeb1dc8e81deea2a67dfa0f1b469b080",
"a100000000000000000000000000000000000000000000000000000000000000",
"7015ddc8d5dfc4be84b0a4bd00f9d26b16e229c60431896093c6defb4faa34b6a4ed932e000e6e61c4246877a5a0b418316e296d5759a0a46b9c7b0cd2fe46d39e42cc3480f1b6cd21b9222d80086eb7bc6af29db8861f3e808053e2819dc397",
"c2d35c660b1773b60299c3af4c07f4cc0957ccee149ee6ad9786b3a43e263b257fcdb7c2c757d00c2bfc535427b6880bae2a3139ce369bc032e5073e99c4d1c179eb17204ead1ee437e67c145de8f293e1c9aa0fdd2f1cda4b9bfab9e12a5288",
"b100000000000000000000000000000000000000000000000000000000000000",
"e53f96627acfa3d6bdd418b703ab500c552b97ad46008797211f2d888d4e59f5575f2e38e4ed2aac84d56537b1c2060773c89f6d1efc530f88ac5d83fe020396805e4a0c9e3dc5de32a0fa45e2de0bde88dd26928f71be6d331ee9cadd2cb094",
"8a258c304d1d066d6dee87cc777f31b9de78479c18dd98d5ac21e9633229c010d90f67d78eddf42c806c9b150af2eb075d5e24ad2f015b1d8a441b18fdd2acef59191d4d127da347922e75c8df0dfa1e367275bb331a9c7a2c00f3177f5a8888",
"c100000000000000000000000000000000000000000000000000000000000000",
"7bb7979191ff113850576f6f32fb74f2a2d2b25fac89ee6c9254a9f7ddc052cf3f7f8fc3a99e0558e4ef5174874e6d0c7bce0007b6005a35c992de87b537e2b2722db36f12a85ec91cc25061ac32094b9a43242201fde7aacb21f9558fa35d15",
"ab449fda6c1312e42fb789880d8e74e771961115ce69d4c45766054074e1315033fec3c045ec8f1332498a5bc90c9b16822c04adc20f2cd668151e47b06914afd2171be6703d42782ba750ceebdfdf971da2f76c79d719a689e80e389a912591",
"d100000000000000000000000000000000000000000000000000000000000000",
"6209cf6dc6da6643afef5d68d0778882ebaa0f5851f77f1b0f588e40f5a6c54bcf68e7add77b7bd570ec18ffcfe5d305e1ed240ba89cb7ec5bdc158d8b7388abc8c9ff6ee8392c67b9bf7e2d224d366fbdd846665ee9443002dabb8069a1e014",
"68d4416d2cedb6a1e39b3dce6c1e135b49b43c239da07db01875a9d84f95ceb53d1a99255d2ae23cd8a8739916524b10879ae8805c381194c59c8b50185d968b1d3f7df9681a6a0324ddd8cb371017c314515652d3375a69348738402b3bb807",
"e100000000000000000000000000000000000000000000000000000000000000",
"deb06b9288d57f7f4838594562822117887c146f328a5933e5b4980e8aa40b020ec468d89a10a51ae5bf179b8cdcd004ee5ac07a7cd06f201aae6cf541f8d57796cc5436cd8f262e3fd1b43dc35510e17b47b34360c73c00734df1187064680f",
"de05f56c69b4bf7630df781efe05b5e13c262f146bc7d746cd5710e7faf6377dac44ffc9eca2e3274d58bfc33cb00d15a6b659617f301bb80b072d79b2f7d9234f20995d82ed87740f542f69e007c3cf9b4a530b63da386a53da99d4e01ce915",
"f100000000000000000000000000000000000000000000000000000000000000",
"15f7a919ce5e43146f3338c4e1fd43e9664ccdd3c1f70ad5b96972407e4a6d1bb9e030e7f37209b16dbfbd2d88d4be045d7bb7cf81ce336b1c2a911ed0e5036e4f70eda356b113d72fd4de31ada32b36aa2b5cdd0ecbf9619b3ea0469383200a",
"b8dbe1f7689d89c5e3b830a5d1d0d51be7c35504f407cdc41cb930afe82c5806b36c776c9408cefab66c1489561c9f114943bd99ffe7df6572fbd0e1fe8f4fd44ba8b0c8d6aeeb54194adfb106d4902c499f437dbd6f3ece71d1b46d3a52128e",
"0100000000000000000000000000000000000000000000000000000000000000",
"4ab3723dcd3ecfc0448dfc9bba6fce7f5618a0c2bc0eb981504a84c568c8c626d33e0809a9332d5a597ad5382ce5250d03284b8261a5fe0d3ad3b3b9c0a6b3887f7c2122c9e3ce3780075dbff3f8e3eebde76ced6667e7febfc02fc8459ef193",
"50fad24cd67da8b0730220f101810c445ad452893c9b864b7ce91b604f984f3fcba3b117352c9d2e206a1777fe5ec113ce5690ddb9f5667da754fae05ef2d16448e4e980a29ff962c19306e6ce5479c6fd4a30c207b696942a4b393ee1e1cc0c",
		};
		for (int i = 0; i < dataHex.length; i += 3) {
			byte[] msg = hexStrToByte(dataHex[i]);
			sig = sec.sign(msg);
			assertBool("sec.sign", byteToHexStr(sig.serialize()).equals(dataHex[i + 1]));
			assertBool("sig.verify", sig.verify(pub, msg));
			sig = sec.signHash(msg);
			assertBool("sec.signHash", byteToHexStr(sig.serialize()).equals(dataHex[i + 2]));
			assertBool("sig.verifyHash", sig.verifyHash(pub, msg));
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
				testHarmonyONE();
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
