function getValue(name) { return document.getElementsByName(name)[0].value }
function setValue(name, val) { document.getElementsByName(name)[0].value = val }
function getText(name) { return document.getElementsByName(name)[0].innerText }
function setText(name, val) { document.getElementsByName(name)[0].innerText = val }

let moduleInited = false

let module = setupWasm('bls_c.wasm', null, function(mod, ns) {
	define_exported_bls(mod)
	define_bls_extra_functions(mod)
	moduleInited = true
	onChangeSelectCurve()
})

function putId(x, msg = "") {
	console.log(msg + ' id=' + Uint8ArrayToHexString(blsIdSerialize(x)))
}
function putSecretKey(x, msg = "") {
	console.log(msg + ' sk=' + Uint8ArrayToHexString(blsSecretKeySerialize(x)))
}
function putPublicKey(x, msg = "") {
	console.log(msg + ' pk=' + Uint8ArrayToHexString(blsPublicKeySerialize(x)))
}
function putSignature(x, msg = "") {
	console.log(msg + ' sig=' + Uint8ArrayToHexString(blsSignatureSerialize(x)))
}

let prevSelectedCurve = -1
function onChangeSelectCurve() {
	if (!moduleInited) return
	let obj = document.selectCurve.curveType
	let idx = obj.selectedIndex
	let curve = obj.options[idx].value
	if (curve == prevSelectedCurve) return
	prevSelectedCurve = curve
	console.log('idx=' + idx)
	let r = blsInit(idx)
	setText('status', r ? 'err:' + r : 'ok')
	setText('curveOrder', blsGetCurveOrder())
}

function rand(val) {
	let x = mclBnFr_malloc()
	mclBnFr_setByCSPRNG(x)
	setValue(val, mclBnFr_getStr(x))
	mcl_free(x)
}

function bench(label, count, func) {
	let start = Date.now()
	for (let i = 0; i < count; i++) {
		func()
	}
	let end = Date.now()
	let t = (end - start) / count
	setText(label, t)
}

function benchPairing() {
	let a = mclBnFr_malloc()
	let P = mclBnG1_malloc()
	let Q = mclBnG2_malloc()
	let e = mclBnGT_malloc()

	let msg = 'hello wasm'

	mclBnFr_setByCSPRNG(a)
	console.log('a=' + mclBnFr_getStr(a))
	mclBnG1_hashAndMapTo(P, 'abc')
	mclBnG2_hashAndMapTo(Q, 'abc')
	console.log('P=' + mclBnG1_getStr(P))
	console.log('Q=' + mclBnG2_getStr(Q))
	bench('time_pairing', 50, () => mclBn_pairing(e, P, Q))
	bench('time_g1mul', 50, () => mclBnG1_mulCT(P, P, a))
	bench('time_g2mul', 50, () => mclBnG2_mulCT(Q, Q, a))
	bench('time_mapToG1', 50, () => mclBnG1_hashAndMapTo(P, msg))

	mcl_free(e)
	mcl_free(Q)
	mcl_free(P)
	mcl_free(a)

	let sec = new BlsSecretKey()
	bench('time_setByCSPRNG', 50, () => sec.setByCSPRNG())
}

function benchBls() {
	let sec = blsSecretKey_malloc()
	let pub = blsPublicKey_malloc()
	let sig = blsSignature_malloc()

	blsSecretKeySetByCSPRNG(sec)
	let msg = "hello wasm"
	bench('time_sign', 50, () => blsSign(sig, sec, msg))
	bench('time_verify', 50, () => blsVerify(sig, pub, msg))

	bls_free(sec)
	bls_free(pub)
	bls_free(sig)
}
function onClickBenchmark() {
	benchPairing()
	benchBls()
}

function onClickTestPairing() {
	document.getElementById('testPairing').disabled = true
	let a = mclBnFr_malloc()
	let b = mclBnFr_malloc()
	let ab = mclBnFr_malloc()
	let P = mclBnG1_malloc()
	let aP = mclBnG1_malloc()
	let Q = mclBnG2_malloc()
	let bQ = mclBnG2_malloc()
	let e1 = mclBnGT_malloc()
	let e2 = mclBnGT_malloc()

	mclBnFr_setStr(a, getValue('a'))
	mclBnFr_setStr(b, getValue('b'))
	mclBnFr_mul(ab, a, b)
	setText('ab', mclBnFr_getStr(ab))

	mclBnG1_hashAndMapTo(P, getValue('hash_P'))
	setText('P', mclBnG1_getStr(P))
	mclBnG2_hashAndMapTo(Q, getValue('hash_Q'))
	setText('Q', mclBnG2_getStr(Q))
	mclBnG1_mul(aP, P, a)
	setText('aP', mclBnG1_getStr(aP))
	mclBnG2_mul(bQ, Q, b)
	setText('bQ', mclBnG2_getStr(bQ))

	mclBn_pairing(e1, P, Q);
	setText('ePQ', mclBnGT_getStr(e1))
	mclBn_pairing(e2, aP, bQ);
	setText('eaPbQ', mclBnGT_getStr(e2))
	mclBnGT_pow(e1, e1, ab)
	setText('ePQab', mclBnGT_getStr(e1))
	setText('verify_pairing', !!mclBnGT_isEqual(e1, e2))

	mcl_free(e2)
	mcl_free(e1)
	mcl_free(bQ)
	mcl_free(Q)
	mcl_free(aP)
	mcl_free(P)
	mcl_free(ab)
	mcl_free(b)
	mcl_free(a)
	document.getElementById('testPairing').disabled = false
}

function Uint8ArrayToHexString(a) {
	let s = ''
	for (let i = 0; i < a.length; i++) {
		s += ('0' + a[i].toString(16)).slice(-2)
	}
	return s
}

function HexStringToUint8Array(s) {
	let n = (s.length + 1) / 2
	let a = new Uint8Array(n)
	for (let i = 0; i < s.length / 2; i++) {
		a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
	}
	if ((s.length & 1) != 0) {
		a[n - 1] = parseInt(s[s.length - 1] + '0', 16)
	}
	return a
}

function onClickTestSignature() {
	let secretKey = blsSecretKey_malloc()
	let publicKey = blsPublicKey_malloc()
	let signature = blsSignature_malloc()

	blsSecretKeySetByCSPRNG(secretKey)
	setText('secretKey', Uint8ArrayToHexString(blsSecretKeySerialize(secretKey)))

	blsGetPublicKey(publicKey, secretKey)
	setText('publicKey', Uint8ArrayToHexString(blsPublicKeySerialize(publicKey)))

	let msg = getValue('msg')
	console.log('msg=' + msg)
	blsSign(signature, secretKey, msg)
	setText('signature', Uint8ArrayToHexString(blsSignatureSerialize(signature)))

	let r = blsVerify(signature, publicKey, msg)	
	setText('verifyResult', r ? 'ok' : 'err')

	bls_free(signature)
	bls_free(publicKey)
	bls_free(secretKey)
}

/*
	return [min, max)
	assume min < max
*/
function randRange(min, max) {
	return min + Math.floor(Math.random() * (max - min))
}
/*
	select k of [0, n)
	@note not uniformal distribution
*/
function randSelect(k, n) {
	let a = []
	let prev = -1
	for (let i = 0; i < k; i++) {
		let v = randRange(prev + 1, n - (k - i) + 1)
		a.push(v)
		prev = v
	}
	return a
}

function evalFunc(y, vec, x) {
	mclBnFr_mul(y, vec[1], x)
	mclBnFr_add(y, y, vec[0])
}

function onClickTestShare()
{
	let k = parseInt(getValue('ss_k'))
	let n = parseInt(getValue('ss_n'))
	let msg = getValue('msg2')
	console.log('k = ' + k)
	console.log('n = ' + n)
	console.log('msg = ' + msg)
	if (n < k) {
		alert('err : n is smaller than k')
		return
	}
	let msk = []
	let mpk = []
	let idVec = []
	let secVec = []
	let pubVec = []
	let sigVec = []

	/*
		setup master secret key
	*/
	for (let i = 0; i < k; i++) {
		let sk = blsSecretKey_malloc()
		blsSecretKeySetByCSPRNG(sk)
		msk.push(sk)

		let pk = blsPublicKey_malloc()
		blsGetPublicKey(pk, sk)
		mpk.push(pk)
	}
	setText('msk', Uint8ArrayToHexString(blsSecretKeySerialize(msk[0])))
	setText('mpk', Uint8ArrayToHexString(blsPublicKeySerialize(mpk[0])))
	{
		let sig = blsSignature_malloc()
		blsSign(sig, msk[0], msg)
		setText('signature2', Uint8ArrayToHexString(blsSignatureSerialize(sig)))
		bls_free(sig)
	}

	/*
		key sharing
	*/
	for (let i = 0; i < n; i++) {
		let id = blsId_malloc()
//		blsIdSetInt(id, i + 1)
		blsSecretKeySetByCSPRNG(id) // Id is same type of SecretKey
		idVec.push(id)
		let sk = blsSecretKey_malloc()
		blsSecretKeyShare(sk, msk, idVec[i])
		secVec.push(sk)

		let pk = blsPublicKey_malloc()
		blsPublicKeyShare(pk, mpk, idVec[i])
		pubVec.push(pk)

		{
			let pk2 = blsPublicKey_malloc()
			blsGetPublicKey(pk2, sk)
			console.log(i + ' : pk == pk2 : ' + mclBnG2_isEqual(pk, pk2))
			bls_free(pk2)
		}

		let sig = blsSignature_malloc()
		blsSign(sig, sk, msg)
		sigVec.push(sig)
		console.log(i + ' : verify msg : ' + blsVerify(sig, pk, msg))
	}

	let o = document.getElementById('idlist')
	let ol = document.createElement('ol')
	let t = ''
	for (let i = 0; i < n; i++) {
		let id = Uint8ArrayToHexString(blsIdSerialize(idVec[i]))
		let sk = Uint8ArrayToHexString(blsSecretKeySerialize(secVec[i]))
		let pk = Uint8ArrayToHexString(blsPublicKeySerialize(pubVec[i]))
		let sig = Uint8ArrayToHexString(blsSignatureSerialize(sigVec[i]))
		t += '<li id="ui"' + i + '"> '
		t += 'id : <span id="id"' + i + '">' + id + '</span><br>'
		t += 'pk : <span id="pk"' + i + '">' + pk + '</span><br>'
		t += 'sk : <span id="sk"' + i + '">' + sk + '</span><br>'
		t += 'sig: <span id="sig"' + i + '">' + sig + '</span><br>'
	}
	ol.innerHTML = t
	o.firstElementChild.innerHTML = ol.innerHTML

	/*
		recover
	*/
	let idxVec = randSelect(k, n)
	setText('idxVec', idxVec.toString())
	let subIdVec = []
	let subSecVec = []
	let subPubVec = []
	let subSigVec = []
	for (let i = 0; i < idxVec.length; i++) {
		let idx = idxVec[i]
		subIdVec.push(idVec[idx])
		subSecVec.push(secVec[idx])
		subPubVec.push(pubVec[idx])
		subSigVec.push(sigVec[idx])
	}
	{
		let sec = blsSecretKey_malloc()
		let pub = blsPublicKey_malloc()
		let sig = blsSignature_malloc()

		blsSecretKeyRecover(sec, subSecVec, subIdVec)
		blsPublicKeyRecover(pub, subPubVec, subIdVec)
		blsSignatureRecover(sig, subSigVec, subIdVec)
		let s = Uint8ArrayToHexString(blsSecretKeySerialize(sec))
		s += s == getText('msk') ? ' :ok' : ' :ng'
		setText('recoverSec', s)
		s = Uint8ArrayToHexString(blsPublicKeySerialize(pub))
		s += s == getText('mpk') ? ' :ok' : ' :ng'
		setText('recoverPub', s)
		s = Uint8ArrayToHexString(blsSignatureSerialize(sig))
		s += s == getText('signature2') ? ' :ok' : ' :ng'
		setText('recoverSig', s)

		bls_free(sig)
		bls_free(pub)
		bls_free(sec)
	}


	for (let i = 0; i < n; i++) {
		bls_free(idVec[i])
		bls_free(secVec[i])
		bls_free(pubVec[i])
		bls_free(sigVec[i])
	}
	for (let i = 0; i < mpk.length; i++) {
		bls_free(mpk[i])
		bls_free(msk[i])
	}
}

function onClickTestMisc()
{
	let idDec = getValue('idDec')
	console.log('idDec=' + idDec)
	var id = new BlsId()
	id.setStr(idDec)
	setText('idDec2', id.getStr())
	setText('idHex', id.getStr(16))
	var sec = new BlsSecretKey()
	sec.setLittleEndian(HexStringToUint8Array(getValue('sec1')))
	var a = sec.serialize()
	setText('secSerialize', Uint8ArrayToHexString(a))
}
