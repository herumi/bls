function getValue(name) { return document.getElementsByName(name)[0].value }
function setValue(name, val) { document.getElementsByName(name)[0].value = val }
function getText(name) { return document.getElementsByName(name)[0].innerText }
function setText(name, val) { document.getElementsByName(name)[0].innerText = val }

function setupWasm(fileName, nameSpace, setupFct) {
	console.log('setupWasm ' + fileName)
	let mod = {}
	fetch(fileName)
		.then(response => response.arrayBuffer())
		.then(buffer => new Uint8Array(buffer))
		.then(binary => {
			mod['wasmBinary'] = binary
			mod['onRuntimeInitialized'] = function() {
				setupFct(mod, nameSpace)
				console.log('setupWasm end')
			}
			Module(mod)
		})
	return mod
}

const MCLBN_CURVE_FP254BNB = 0
const MCLBN_CURVE_FP382_1 = 1
const MCLBN_CURVE_FP382_2 = 2

const MCLBN_FP_UNIT_SIZE = 6

let moduleInited = false

let module = setupWasm('bls_c.wasm', null, function(mod, ns) {
	define_exported_bls(mod)
	define_extra_functions(mod)
	moduleInited = true
	onChangeSelectCurve()
})

function define_extra_functions(mod) {
	wrap_outputString = function(func, doesReturnString = true) {
		return function(x, ioMode = 0) {
			let maxBufSize = 2048
			let stack = mod.Runtime.stackSave()
			let pos = mod.Runtime.stackAlloc(maxBufSize)
			let n = func(pos, maxBufSize, x, ioMode)
			if (n < 0) {
				throw('err gen_str:' + x)
			}
			if (doesReturnString) {
				let s = ''
				for (let i = 0; i < n; i++) {
					s += String.fromCharCode(mod.HEAP8[pos + i])
				}
				mod.Runtime.stackRestore(stack)
				return s
			} else {
				let a = new Uint8Array(n)
				for (let i = 0; i < n; i++) {
					a[i] = mod.HEAP8[pos + i]
				}
				mod.Runtime.stackRestore(stack)
				return a
			}
		}
	}
	wrap_outputArray = function(func) {
		return wrap_outputString(func, false)
	}
	wrap_input0 = function(func, returnValue = false) {
		return function(buf, ioMode = 0) {
			let stack = mod.Runtime.stackSave()
			let pos = mod.Runtime.stackAlloc(buf.length)
			if (typeof(buf) == "string") {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf.charCodeAt(i)
				}
			} else {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf[i]
				}
			}
			let r = func(pos, buf.length, ioMode)
			mod.Runtime.stackRestore(stack)
			if (returnValue) return r
			if (r) throw('err wrap_input0 ' + buf)
		}
	}
	wrap_input1 = function(func, returnValue = false) {
		return function(x1, buf, ioMode = 0) {
			let stack = mod.Runtime.stackSave()
			let pos = mod.Runtime.stackAlloc(buf.length)
			if (typeof(buf) == "string") {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf.charCodeAt(i)
				}
			} else {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf[i]
				}
			}
			let r = func(x1, pos, buf.length, ioMode)
			mod.Runtime.stackRestore(stack)
			if (returnValue) return r
			if (r) throw('err wrap_input1 ' + buf)
		}
	}
	wrap_input2 = function(func, returnValue = false) {
		return function(x1, x2, buf, ioMode = 0) {
			let stack = mod.Runtime.stackSave()
			let pos = mod.Runtime.stackAlloc(buf.length)
			if (typeof(buf) == "string") {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf.charCodeAt(i)
				}
			} else {
				for (let i = 0; i < buf.length; i++) {
					mod.HEAP8[pos + i] = buf[i]
				}
			}
			let r = func(x1, x2, pos, buf.length, ioMode)
			mod.Runtime.stackRestore(stack)
			if (returnValue) return r
			if (r) throw('err wrap_input2 ' + buf)
		}
	}
	wrap_keyShare = function(func, dataSize) {
		return function(x, vec, id) {
			let k = vec.length
			let p = mod._malloc(dataSize * k)
			for (let i = 0; i < k; i++) {
				mod._memcpy(p + i * dataSize, vec[i], dataSize)
			}
			let r = func(x, p, k, id)
			mod._free(p)
			if (r) throw('keyShare ' + k)
		}
	}
	wrap_recover = function(func, dataSize, idDataSize) {
		return function(x, vec, idVec) {
			let n = vec.length
			let p = mod._malloc(dataSize * n)
			let q = mod._malloc(idDataSize * n)
			for (let i = 0; i < n; i++) {
				mod._memcpy(p + i * dataSize, vec[i], dataSize)
				mod._memcpy(q + i * idDataSize, idVec[i], idDataSize)
			}
			let r = func(x, p, q, n)
			mod._free(q)
			mod._free(p)
			if (r) throw('recover ' + n)
		}
	}
	///////////////////////////////////////////////////////////////
	const FR_SIZE = MCLBN_FP_UNIT_SIZE * 8
	const G1_SIZE = FR_SIZE * 3
	const G2_SIZE = FR_SIZE * 3 * 2
	const GT_SIZE = FR_SIZE * 12

	const ID_SIZE = FR_SIZE
	const SECRETKEY_SIZE = FR_SIZE
	const PUBLICKEY_SIZE = G2_SIZE
	const SIGNATURE_SIZE = G1_SIZE

	mclBnFr_malloc = function() {
		return mod._malloc(FR_SIZE)
	}
	mcl_free = function(x) {
		mod._free(x)
	}
	mclBnFr_deserialize = wrap_input1(_mclBnFr_deserialize)
	mclBnFr_setLittleEndian = wrap_input1(_mclBnFr_setLittleEndian)
	mclBnFr_setStr = wrap_input1(_mclBnFr_setStr)
	mclBnFr_getStr = wrap_outputString(_mclBnFr_getStr)
	mclBnFr_setHashOf = wrap_input1(_mclBnFr_setHashOf)

	///////////////////////////////////////////////////////////////
	mclBnG1_malloc = function() {
		return mod._malloc(G1_SIZE)
	}
	mclBnG1_setStr = wrap_input1(_mclBnG1_setStr)
	mclBnG1_getStr = wrap_outputString(_mclBnG1_getStr)
	mclBnG1_deserialize = wrap_input1(_mclBnG1_deserialize)
	mclBnG1_serialize = wrap_outputArray(_mclBnG1_serialize)
	mclBnG1_hashAndMapTo = wrap_input1(_mclBnG1_hashAndMapTo)

	///////////////////////////////////////////////////////////////
	mclBnG2_malloc = function() {
		return mod._malloc(G2_SIZE)
	}
	mclBnG2_setStr = wrap_input1(_mclBnG2_setStr)
	mclBnG2_getStr = wrap_outputString(_mclBnG2_getStr)
	mclBnG2_deserialize = wrap_input1(_mclBnG2_deserialize)
	mclBnG2_serialize = wrap_outputArray(_mclBnG2_serialize)
	mclBnG2_hashAndMapTo = wrap_input1(_mclBnG2_hashAndMapTo)

	///////////////////////////////////////////////////////////////
	mclBnGT_malloc = function() {
		return mod._malloc(GT_SIZE)
	}
	mclBnGT_deserialize = wrap_input1(_mclBnGT_deserialize)
	mclBnGT_serialize = wrap_outputArray(_mclBnGT_serialize)
	mclBnGT_setStr = wrap_input1(_mclBnGT_setStr)
	mclBnGT_getStr = wrap_outputString(_mclBnGT_getStr)
	///////////////////////////////////////////////////////////////
	bls_free = mcl_free
	blsId_malloc = mclBnFr_malloc
	blsSecretKey_malloc = mclBnFr_malloc
	blsPublicKey_malloc = mclBnG2_malloc
	blsSignature_malloc = mclBnG1_malloc

	blsGetCurveOrder = wrap_outputString(_blsGetCurveOrder)
	blsGetFieldOrder = wrap_outputString(_blsGetFieldOrder)

	blsIdSetDecStr = wrap_input1(_blsIdSetDecStr)
	blsIdSetHexStr = wrap_input1(_blsIdSetHexStr)
	blsIdGetDecStr = wrap_outputArray(_blsIdGetDecStr)
	blsIdGetHexStr = wrap_outputArray(_blsIdGetHexStr)

	blsIdSerialize = wrap_outputArray(_blsIdSerialize)
	blsSecretKeySerialize = wrap_outputArray(_blsSecretKeySerialize)
	blsPublicKeySerialize = wrap_outputArray(_blsPublicKeySerialize)
	blsSignatureSerialize = wrap_outputArray(_blsSignatureSerialize)

	blsIdDeserialize = wrap_input1(_blsIdDeserialize)
	blsSecretKeyDeserialize = wrap_input1(_blsSecretKeyDeserialize)
	blsPublicKeyDeserialize = wrap_input1(_blsPublicKeyDeserialize)
	blsSignatureDeserialize = wrap_input1(_blsSignatureDeserialize)

	blsHashToSecretKey = wrap_input1(_blsHashToSecretKey)
	blsSign = wrap_input2(_blsSign)
	blsVerify = wrap_input2(_blsVerify, true)

	blsSecretKeyShare = wrap_keyShare(_blsSecretKeyShare, SECRETKEY_SIZE)
	blsPublicKeyShare = wrap_keyShare(_blsPublicKeyShare, PUBLICKEY_SIZE)

	blsSecretKeyRecover = wrap_recover(_blsSecretKeyRecover, SECRETKEY_SIZE, ID_SIZE)
	blsPublicKeyRecover = wrap_recover(_blsPublicKeyRecover, PUBLICKEY_SIZE, ID_SIZE)
	blsSignatureRecover = wrap_recover(_blsSignatureRecover, SIGNATURE_SIZE, ID_SIZE)
}

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
	let r = blsInit(idx, MCLBN_FP_UNIT_SIZE)
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
	let a = new Uint8Array(s.length / 2)
	for (let i = 0; i < s.length / 2; i++) {
		a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
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

