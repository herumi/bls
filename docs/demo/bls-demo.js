function getValue(name) { return document.getElementsByName(name)[0].value }
function setValue(name, val) { document.getElementsByName(name)[0].value = val }
function getText(name) { return document.getElementsByName(name)[0].innerText }
function setText(name, val) { document.getElementsByName(name)[0].innerText = val }

(function() {
	bls.init(function() {
		setText('status', 'ok')
		setText('curveOrder', bls.capi.blsGetCurveOrder())
	})
})()

let prevSelectedCurve = -1
function onChangeSelectCurve() {
	let obj = document.selectCurve.curveType
	let idx = obj.selectedIndex
	let curve = obj.options[idx].value
	if (curve == prevSelectedCurve) return
	prevSelectedCurve = curve
	console.log('idx=' + idx)
	let r = bls.capi.blsInit(idx)
	setText('status', r ? 'err:' + r : 'ok')
	setText('curveOrder', bls.capi.blsGetCurveOrder())
}

function rand(val) {
	let x = new she.Id()
	x.setByCSPRNG()
	setValue(val, c.toHexStr())
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
	let capi = bls.capi
	let a = capi.mclBnFr_malloc()
	let P = capi.mclBnG1_malloc()
	let Q = capi.mclBnG2_malloc()
	let e = capi.mclBnGT_malloc()

	let msg = 'hello wasm'

	capi.mclBnFr_setByCSPRNG(a)
	console.log('a=' + capi.mclBnFr_getStr(a))
	capi.mclBnG1_hashAndMapTo(P, 'abc')
	capi.mclBnG2_hashAndMapTo(Q, 'abc')
	console.log('P=' + capi.mclBnG1_getStr(P))
	console.log('Q=' + capi.mclBnG2_getStr(Q))
	bench('time_pairing', 50, () => capi.mclBn_pairing(e, P, Q))
	bench('time_g1mul', 50, () => capi.mclBnG1_mulCT(P, P, a))
	bench('time_g2mul', 50, () => capi.mclBnG2_mulCT(Q, Q, a))
	bench('time_mapToG1', 50, () => capi.mclBnG1_hashAndMapTo(P, msg))

	capi.mcl_free(e)
	capi.mcl_free(Q)
	capi.mcl_free(P)

	let sec = new bls.SecretKey()
	bench('time_setByCSPRNG', 50, () => sec.setByCSPRNG())
}

function benchBls() {
	let capi = bls.capi
	let sec = capi.blsSecretKey_malloc()
	let pub = capi.blsPublicKey_malloc()
	let sig = capi.blsSignature_malloc()

	capi.blsSecretKeySetByCSPRNG(sec)
	let msg = "hello wasm"
	bench('time_sign', 50, () => capi.blsSign(sig, sec, msg))
	bench('time_verify', 50, () => capi.blsVerify(sig, pub, msg))

	capi.bls_free(sec)
	capi.bls_free(pub)
	capi.bls_free(sig)
	sec = new bls.SecretKey()
	sec.setByCSPRNG()
	pub = sec.getPublicKey()
	bench('time_sign_class', 50, () => sec.sign(msg))
	sig = sec.sign(msg)
	bench('time_verify_class', 50, () => pub.verify(sig, msg))
}
function onClickBenchmark() {
	benchPairing()
	benchBls()
}

function onClickTestPairing() {
	let capi = bls.capi
	document.getElementById('testPairing').disabled = true
	let a = capi.mclBnFr_malloc()
	let b = capi.mclBnFr_malloc()
	let ab = capi.mclBnFr_malloc()
	let P = capi.mclBnG1_malloc()
	let aP = capi.mclBnG1_malloc()
	let Q = capi.mclBnG2_malloc()
	let bQ = capi.mclBnG2_malloc()
	let e1 = capi.mclBnGT_malloc()
	let e2 = capi.mclBnGT_malloc()

	capi.mclBnFr_setStr(a, getValue('a'))
	capi.mclBnFr_setStr(b, getValue('b'))
	capi.mclBnFr_mul(ab, a, b)
	setText('ab', capi.mclBnFr_getStr(ab))

	capi.mclBnG1_hashAndMapTo(P, getValue('hash_P'))
	setText('P', capi.mclBnG1_getStr(P))
	capi.mclBnG2_hashAndMapTo(Q, getValue('hash_Q'))
	setText('Q', capi.mclBnG2_getStr(Q))
	capi.mclBnG1_mul(aP, P, a)
	setText('aP', capi.mclBnG1_getStr(aP))
	capi.mclBnG2_mul(bQ, Q, b)
	setText('bQ', capi.mclBnG2_getStr(bQ))

	capi.mclBn_pairing(e1, P, Q);
	setText('ePQ', capi.mclBnGT_getStr(e1))
	capi.mclBn_pairing(e2, aP, bQ);
	setText('eaPbQ', capi.mclBnGT_getStr(e2))
	capi.mclBnGT_pow(e1, e1, ab)
	setText('ePQab', capi.mclBnGT_getStr(e1))
	setText('verify_pairing', !!capi.mclBnGT_isEqual(e1, e2))

	capi.mcl_free(e2)
	capi.mcl_free(e1)
	capi.mcl_free(bQ)
	capi.mcl_free(Q)
	capi.mcl_free(aP)
	capi.mcl_free(P)
	capi.mcl_free(ab)
	capi.mcl_free(b)
	capi.mcl_free(a)
	document.getElementById('testPairing').disabled = false
}

function onClickTestSignature() {
	let sec = new bls.SecretKey()

	sec.setByCSPRNG()
	setText('secretKey', sec.toHexStr())

	let pub = sec.getPublicKey()
	setText('publicKey', pub.toHexStr())

	let msg = getValue('msg')
	console.log('msg=' + msg)
	let sig = sec.sign(msg)
	setText('signature', sig.toHexStr())

	let r = pub.verify(sig, msg)
	setText('verifyResult', r ? 'ok' : 'err')
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

function onClickTestMisc()
{
	let idDec = getValue('idDec')
	console.log('idDec=' + idDec)
	var id = new bls.Id()
	id.setStr(idDec)
	setText('idDec2', id.getStr())
	setText('idHex', id.getStr(16))
	var sec = new bls.SecretKey()
	sec.setLittleEndian(bls.fromHexStr(getValue('sec1')))
	var a = sec.serialize()
	setText('secSerialize', bls.toHexStr(a))
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
		let sk = new bls.SecretKey()
		sk.setByCSPRNG()
		msk.push(sk)

		let pk = sk.getPublicKey()
		mpk.push(pk)
	}
	setText('msk', bls.toHexStr(msk[0].serialize()))
	setText('mpk', bls.toHexStr(mpk[0].serialize()))
	{
		let sig = msk[0].sign(msg)
		setText('signature2', bls.toHexStr(sig.serialize()))
		console.log('mpk[0] verify ' + mpk[0].verify(sig, msg))
	}

	/*
		key sharing
	*/
	for (let i = 0; i < n; i++) {
		let id = new bls.Id()
//		blsIdSetInt(id, i + 1)
		id.setByCSPRNG()
		idVec.push(id)
		let sk = new bls.SecretKey()
		sk.share(msk, idVec[i])
		secVec.push(sk)

		let pk = new bls.PublicKey()
		pk.share(mpk, idVec[i])
		pubVec.push(pk)

		let sig = sk.sign(msg)
		sigVec.push(sig)
		console.log(i + ' : verify msg : ' + pk.verify(sig, msg))
	}

	let o = document.getElementById('idlist')
	let ol = document.createElement('ol')
	let t = ''
	for (let i = 0; i < n; i++) {
		let id = idVec[i].toHexStr()
		let sk = secVec[i].toHexStr()
		let pk = pubVec[i].toHexStr()
		let sig = sigVec[i].toHexStr()
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
		let sec = new bls.SecretKey()
		let pub = new bls.PublicKey()
		let sig = new bls.Signature()

		sec.recover(subSecVec, subIdVec)
		pub.recover(subPubVec, subIdVec)
		sig.recover(subSigVec, subIdVec)
		let s = sec.toHexStr()
		s += s == getText('msk') ? ' :ok' : ' :ng'
		setText('recoverSec', s)
		s = pub.toHexStr()
		s += s == getText('mpk') ? ' :ok' : ' :ng'
		setText('recoverPub', s)
		s = sig.toHexStr()
		s += s == getText('signature2') ? ' :ok' : ' :ng'
		setText('recoverSig', s)
	}
}
