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

const BLS_ID_SIZE = MCLBN_FP_UNIT_SIZE * 8
const BLS_SECRETKEY_SIZE = BLS_ID_SIZE
const BLS_PUBLICKEY_SIZE = BLS_ID_SIZE * 3 * 2
const BLS_SIGNATURE_SIZE = BLS_ID_SIZE * 3

BlsId = function() {
	this.a_ = new Uint32Array(BLS_ID_SIZE / 4)
}
BlsSecretKey = function() {
	this.a_ = new Uint32Array(BLS_SECRETKEY_SIZE / 4)
}
BlsPublicKey = function() {
	this.a_ = new Uint32Array(BLS_PUBLICKEY_SIZE / 4)
}
BlsSignature = function() {
	this.a_ = new Uint32Array(BLS_SIGNATURE_SIZE / 4)
}

function define_bls_extra_functions(mod) {
	ptrToStr = function(pos, n) {
		let s = ''
			for (let i = 0; i < n; i++) {
			s += String.fromCharCode(mod.HEAP8[pos + i])
		}
		return s
	}
	Uint8ArrayToMem = function(pos, buf) {
		for (let i = 0; i < buf.length; i++) {
			mod.HEAP8[pos + i] = buf[i]
		}
	}
	AsciiStrToMem = function(pos, s) {
		for (let i = 0; i < s.length; i++) {
			mod.HEAP8[pos + i] = s.charCodeAt(i)
		}
	}
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
				let s = ptrToStr(pos, n)
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
				AsciiStrToMem(pos, buf)
			} else {
				Uint8ArrayToMem(pos, buf)
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
				AsciiStrToMem(pos, buf)
			} else {
				Uint8ArrayToMem(pos, buf)
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
				AsciiStrToMem(pos, buf)
			} else {
				Uint8ArrayToMem(pos, buf)
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

	blsInit = function(curveType) {
		return _blsInit(curveType, MCLBN_FP_UNIT_SIZE)
	}

	blsGetCurveOrder = wrap_outputString(_blsGetCurveOrder)
	blsGetFieldOrder = wrap_outputString(_blsGetFieldOrder)

	blsIdSetDecStr = wrap_input1(_blsIdSetDecStr)
	blsIdSetHexStr = wrap_input1(_blsIdSetHexStr)
	blsIdGetDecStr = wrap_outputString(_blsIdGetDecStr)
	blsIdGetHexStr = wrap_outputString(_blsIdGetHexStr)

	blsSecretKeySetDecStr = wrap_input1(_blsSecretKeySetDecStr)
	blsSecretKeySetHexStr = wrap_input1(_blsSecretKeySetHexStr)
	blsSecretKeyGetDecStr = wrap_outputString(_blsSecretKeyGetDecStr)
	blsSecretKeyGetHexStr = wrap_outputString(_blsSecretKeyGetHexStr)

	blsIdSerialize = wrap_outputArray(_blsIdSerialize)
	blsSecretKeySerialize = wrap_outputArray(_blsSecretKeySerialize)
	blsPublicKeySerialize = wrap_outputArray(_blsPublicKeySerialize)
	blsSignatureSerialize = wrap_outputArray(_blsSignatureSerialize)

	blsIdDeserialize = wrap_input1(_blsIdDeserialize)
	blsSecretKeyDeserialize = wrap_input1(_blsSecretKeyDeserialize)
	blsPublicKeyDeserialize = wrap_input1(_blsPublicKeyDeserialize)
	blsSignatureDeserialize = wrap_input1(_blsSignatureDeserialize)

	blsSecretKeySetLittleEndian = wrap_input1(_blsSecretKeySetLittleEndian)
	blsHashToSecretKey = wrap_input1(_blsHashToSecretKey)
	blsSign = wrap_input2(_blsSign)
	blsVerify = wrap_input2(_blsVerify, true)

	blsSecretKeyShare = wrap_keyShare(_blsSecretKeyShare, BLS_SECRETKEY_SIZE)
	blsPublicKeyShare = wrap_keyShare(_blsPublicKeyShare, BLS_PUBLICKEY_SIZE)

	blsSecretKeyRecover = wrap_recover(_blsSecretKeyRecover, BLS_SECRETKEY_SIZE, BLS_ID_SIZE)
	blsPublicKeyRecover = wrap_recover(_blsPublicKeyRecover, BLS_PUBLICKEY_SIZE, BLS_ID_SIZE)
	blsSignatureRecover = wrap_recover(_blsSignatureRecover, BLS_SIGNATURE_SIZE, BLS_ID_SIZE)

	let crypto = window.crypto || window.msCrypto

	let copyToUint32Array = function(a, pos) {
		for (let i = 0; i < a.length; i++) {
			a[i] = mod.HEAP32[pos / 4 + i]
		}
	}
	let copyFromUint32Array = function(pos, a) {
		for (let i = 0; i < a.length; i++) {
			mod.HEAP32[pos / 4 + i] = a[i]
		}
	}
	let callSetter = function(func, a, p1, p2) {
		let pos = mod._malloc(a.length * 4)
		func(pos, p1, p2) // p1, p2 may be undefined
		copyToUint32Array(a, pos)
		mod._free(pos)
	}
	let callGetter = function(func, a, p1, p2) {
		let pos = mod._malloc(a.length * 4)
		mod.HEAP32.set(a, pos / 4)
		let s = func(pos, p1, p2)
		mod._free(pos)
		return s
	}
	let callModifier = function(func, a, p1, p2) {
		let pos = mod._malloc(a.length * 4)
		mod.HEAP32.set(a, pos / 4)
		func(pos, p1, p2) // p1, p2 may be undefined
		copyToUint32Array(a, pos)
		mod._free(pos)
	}
	/// BlsId
	BlsId.prototype.setInt = function(x) {
		callSetter(blsIdSetInt, this.a_, x)
	}
	BlsId.prototype.setByCSPRNG = function() {
		callSetter(blsSecretKeySetByCSPRNG, this.a_) // same type of BlsSecretKey
	}
	BlsId.prototype.setStr = function(s, base = 10) {
		switch (base) {
		case 10:
			callSetter(blsIdSetDecStr, this.a_, s)
			return
		case 16:
			callSetter(blsIdSetHexStr, this.a_, s)
			return
		default:
			throw('BlsId.setStr:bad base:' + base)
		}
	}
	BlsId.prototype.deserialize = function(s) {
		callSetter(blsIdDeserialize, this.a_, s)
	}
	BlsId.prototype.getStr = function(base = 10) {
		switch (base) {
		case 10:
			return callGetter(blsIdGetDecStr, this.a_)
		case 16:
			return callGetter(blsIdGetHexStr, this.a_)
		default:
			throw('BlsId.getStr:bad base:' + base)
		}
	}
	BlsId.prototype.serialize = function() {
		return callGetter(blsIdSerialize, this.a_)
	}
	/// BlsSecretKey
	BlsSecretKey.prototype.setInt = function(x) {
		callSetter(blsIdSetInt, this.a_, x) // same as Id
	}
	BlsSecretKey.prototype.deserialize = function(s) {
		callSetter(blsSecretKeyDeserialize, this.a_, s)
	}
	BlsSecretKey.prototype.setLittleEndian = function(s) {
		callSetter(blsSecretKeySetLittleEndian, this.a_, s)
	}
	BlsSecretKey.prototype.serialize = function() {
		return callGetter(blsSecretKeySerialize, this.a_)
	}
	BlsSecretKey.prototype.setHashOf = function(s) {
		callSetter(blsHashToSecretKey, this.a_, s)
	}
	BlsSecretKey.prototype.setByCSPRNG = function() {
		let a = new Uint8Array(BLS_SECRETKEY_SIZE)
		crypto.getRandomValues(a)
		this.setLittleEndian(a)
//		callSetter(blsSecretKeySetByCSPRNG, this.a_)
	}
	// return BlsPublicKey
	BlsSecretKey.prototype.getPublicKey = function() {
		let pub = new BlsPublicKey()
		let stack = mod.Runtime.stackSave()
		let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
		let pubPos = mod.Runtime.stackAlloc(pub.a_.length * 4)
		mod.HEAP32.set(this.a_, secPos / 4)
		blsGetPublicKey(pubPos, secPos)
		copyToUint32Array(pub.a_, pubPos)
		mod.Runtime.stackRestore(stack)
		return pub
	}
	/*
		input
		m : message (string or Uint8Array)
		return
		BlsSignature
	*/
	BlsSecretKey.prototype.sign = function(m) {
		let sig = new BlsSignature()
		let stack = mod.Runtime.stackSave()
		let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
		let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
		mod.HEAP32.set(this.a_, secPos / 4)
		blsSign(sigPos, secPos, m)
		copyToUint32Array(sig.a_, sigPos)
		mod.Runtime.stackRestore(stack)
		return sig
	}
	let share = function(func, a, size, vec, id) {
		let stack = mod.Runtime.stackSave()
		let pos = mod.Runtime.stackAlloc(a.length * 4)
		let idPos = mod.Runtime.stackAlloc(id.a_.length * 4)
		mod.HEAP32.set(a, pos / 4)
		mod.HEAP32.set(id.a_, idPos / 4)
		let vecPos = mod._malloc(size * vec.length)
		for (let i = 0; i < vec.length; i++) {
			copyFromUint32Array(vecPos + size * i, vec[i].a_)
		}
		func(pos, vecPos, vec.length, idPos)
		mod._free(vecPos)
		copyToUint32Array(a, pos)
		mod.Runtime.stackRestore(stack)
	}
	let recover = function(func, a, size, vec, idVec) {
		let n = vec.length
		if (n != idVec.length) throw('recover:bad length')
		let stack = mod.Runtime.stackSave()
		let secPos = mod.Runtime.stackAlloc(a.length * 4)
		let vecPos = mod._malloc(size * n)
		let idVecPos = mod._malloc(BLS_ID_SIZE * n)
		for (let i = 0; i < n; i++) {
			copyFromUint32Array(vecPos + size * i, vec[i].a_)
			copyFromUint32Array(idVecPos + BLS_ID_SIZE * i, idVec[i].a_)
		}
		func(secPos, vecPos, idVecPos, n)
		mod._free(idVecPos)
		mod._free(vecPos)
		copyToUint32Array(a, secPos)
		mod.Runtime.stackRestore(stack)
	}
	/*
		set shared BlsSecretKey by msk and id
		input
		msk : master secret key(array of BlsSecretKey)
		id : BlsId
	*/
	BlsSecretKey.prototype.share = function(msk, id) {
		share(_blsSecretKeyShare, this.a_, BLS_SECRETKEY_SIZE, msk, id)
	}
	BlsPublicKey.prototype.share = function(msk, id) {
		share(_blsPublicKeyShare, this.a_, BLS_PUBLICKEY_SIZE, msk, id)
	}
	/*
		recover BlsSecretKey from (secVec, idVec)
		secVec : array of BlsSecretKey
	*/
	BlsSecretKey.prototype.recover = function(secVec, idVec) {
		recover(_blsSecretKeyRecover, this.a_, BLS_SECRETKEY_SIZE, secVec, idVec)
	}
	BlsPublicKey.prototype.recover = function(secVec, idVec) {
		recover(_blsPublicKeyRecover, this.a_, BLS_PUBLICKEY_SIZE, secVec, idVec)
	}
	BlsSignature.prototype.recover = function(secVec, idVec) {
		recover(_blsSignatureRecover, this.a_, BLS_SIGNATURE_SIZE, secVec, idVec)
	}
	/// BlsPublicKey
	BlsPublicKey.prototype.deserialize = function(s) {
		callSetter(blsPublicKeyDeserialize, this.a_, s)
	}
	BlsPublicKey.prototype.serialize = function() {
		return callGetter(blsPublicKeySerialize, this.a_)
	}
	BlsPublicKey.prototype.verify = function(sig, m) {
		let stack = mod.Runtime.stackSave()
		let pubPos = mod.Runtime.stackAlloc(this.a_.length * 4)
		let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
		mod.HEAP32.set(this.a_, pubPos / 4)
		mod.HEAP32.set(sig.a_, sigPos / 4)
		let r = blsVerify(sigPos, pubPos, m)
		mod.Runtime.stackRestore(stack)
		return r != 0
	}
	/// BlsSignature
	BlsSignature.prototype.deserialize = function(s) {
		callSetter(blsSignatureDeserialize, this.a_, s)
	}
	BlsSignature.prototype.serialize = function() {
		return callGetter(blsSignatureSerialize, this.a_)
	}
}
