(function(return_bls) {
	if (typeof exports === 'object') {
		module.exports = return_bls()
	} else {
		window.bls = return_bls()
	}
})(function() {
	const crypto = window.crypto || window.msCrypto

	const MCLBN_CURVE_FP254BNB = 0
	const MCLBN_CURVE_FP382_1 = 1
	const MCLBN_CURVE_FP382_2 = 2

	const MCLBN_FP_UNIT_SIZE = 6

	const MCLBN_FP_SIZE = MCLBN_FP_UNIT_SIZE * 8
	const MCLBN_G1_SIZE = MCLBN_FP_SIZE * 3
	const MCLBN_G2_SIZE = MCLBN_FP_SIZE * 6
	const MCLBN_GT_SIZE = MCLBN_FP_SIZE * 12

	const BLS_ID_SIZE = MCLBN_FP_UNIT_SIZE * 8
	const BLS_SECRETKEY_SIZE = BLS_ID_SIZE
	const BLS_PUBLICKEY_SIZE = BLS_ID_SIZE * 3 * 2
	const BLS_SIGNATURE_SIZE = BLS_ID_SIZE * 3

	let mod = {}
	let capi = {}
	let self = {}
	self.mod = mod
	self.capi = capi

	const setupWasm = function(fileName, nameSpace, setupFct) {
		console.log('setupWasm ' + fileName)
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
	const ptrToStr = function(pos, n) {
		let s = ''
			for (let i = 0; i < n; i++) {
			s += String.fromCharCode(mod.HEAP8[pos + i])
		}
		return s
	}
	const Uint8ArrayToMem = function(pos, buf) {
		for (let i = 0; i < buf.length; i++) {
			mod.HEAP8[pos + i] = buf[i]
		}
	}
	const AsciiStrToMem = function(pos, s) {
		for (let i = 0; i < s.length; i++) {
			mod.HEAP8[pos + i] = s.charCodeAt(i)
		}
	}
	const copyToUint32Array = function(a, pos) {
		for (let i = 0; i < a.length; i++) {
			a[i] = mod.HEAP32[pos / 4 + i]
		}
	}
	const copyFromUint32Array = function(pos, a) {
		for (let i = 0; i < a.length; i++) {
			mod.HEAP32[pos / 4 + i] = a[i]
		}
	}
	self.toHex = function(a, start, n) {
		let s = ''
		for (let i = 0; i < n; i++) {
			s += ('0' + a[start + i].toString(16)).slice(-2)
		}
		return s
	}
	// Uint8Array to hex string
	self.toHexStr = function(a) {
		return self.toHex(a, 0, a.length)
	}
	// hex string to Uint8Array
	self.fromHexStr = function(s) {
		if (s.length & 1) throw('fromHexStr:length must be even ' + s.length)
		let n = s.length / 2
		let a = new Uint8Array(n)
		for (let i = 0; i < n; i++) {
			a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
		}
		return a
	}

	const wrap_outputString = function(func, doesReturnString = true) {
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
	const wrap_outputArray = function(func) {
		return wrap_outputString(func, false)
	}
	/*
		argNum : n
		func(x0, ..., x_(n-1), buf, ioMode)
		=> func(x0, ..., x_(n-1), pos, buf.length, ioMode)
	*/
	const wrap_input = function(func, argNum, returnValue = false) {
		return function() {
			const args = [...arguments]
			let buf = args[argNum]
			let ioMode = args[argNum + 1] // may undefined
			let stack = mod.Runtime.stackSave()
			let pos = mod.Runtime.stackAlloc(buf.length)
			if (typeof(buf) == "string") {
				AsciiStrToMem(pos, buf)
			} else {
				Uint8ArrayToMem(pos, buf)
			}
			let r = func(...args.slice(0, argNum), pos, buf.length, ioMode)
			mod.Runtime.stackRestore(stack)
			if (returnValue) return r
			if (r) throw('err wrap_input ' + buf)
		}
	}
	const callSetter = function(func, a, p1, p2) {
		let pos = mod._malloc(a.length * 4)
		func(pos, p1, p2) // p1, p2 may be undefined
		copyToUint32Array(a, pos)
		mod._free(pos)
	}
	const callGetter = function(func, a, p1, p2) {
		let pos = mod._malloc(a.length * 4)
		mod.HEAP32.set(a, pos / 4)
		let s = func(pos, p1, p2)
		mod._free(pos)
		return s
	}
	const wrap_keyShare = function(func, dataSize) {
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
	const wrap_recover = function(func, dataSize, idDataSize) {
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
	const callShare = function(func, a, size, vec, id) {
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
	const callRecover = function(func, a, size, vec, idVec) {
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
	const define_extra_functions = function(mod) {
		capi.mclBnFr_malloc = function() {
			return mod._malloc(MCLBN_FP_SIZE)
		}
		capi.mcl_free = function(x) {
			mod._free(x)
		}
		capi.mclBnFr_deserialize = wrap_input(capi._mclBnFr_deserialize, 1)
		capi.mclBnFr_setLittleEndian = wrap_input(capi._mclBnFr_setLittleEndian, 1)
		capi.mclBnFr_setStr = wrap_input(capi._mclBnFr_setStr, 1)
		capi.mclBnFr_getStr = wrap_outputString(capi._mclBnFr_getStr)
		capi.mclBnFr_setHashOf = wrap_input(capi._mclBnFr_setHashOf, 1)

		///////////////////////////////////////////////////////////////
		capi.mclBnG1_malloc = function() {
			return mod._malloc(MCLBN_G1_SIZE)
		}
		capi.mclBnG1_setStr = wrap_input(capi._mclBnG1_setStr, 1)
		capi.mclBnG1_getStr = wrap_outputString(capi._mclBnG1_getStr)
		capi.mclBnG1_deserialize = wrap_input(capi._mclBnG1_deserialize, 1)
		capi.mclBnG1_serialize = wrap_outputArray(capi._mclBnG1_serialize)
		capi.mclBnG1_hashAndMapTo = wrap_input(capi._mclBnG1_hashAndMapTo, 1)

		///////////////////////////////////////////////////////////////
		capi.mclBnG2_malloc = function() {
			return mod._malloc(MCLBN_G2_SIZE)
		}
		capi.mclBnG2_setStr = wrap_input(capi._mclBnG2_setStr, 1)
		capi.mclBnG2_getStr = wrap_outputString(capi._mclBnG2_getStr)
		capi.mclBnG2_deserialize = wrap_input(capi._mclBnG2_deserialize, 1)
		capi.mclBnG2_serialize = wrap_outputArray(capi._mclBnG2_serialize)
		capi.mclBnG2_hashAndMapTo = wrap_input(capi._mclBnG2_hashAndMapTo, 1)

		///////////////////////////////////////////////////////////////
		capi.mclBnGT_malloc = function() {
			return mod._malloc(MCLBN_GT_SIZE)
		}
		capi.mclBnGT_deserialize = wrap_input(capi._mclBnGT_deserialize, 1)
		capi.mclBnGT_serialize = wrap_outputArray(capi._mclBnGT_serialize)
		capi.mclBnGT_setStr = wrap_input(capi._mclBnGT_setStr, 1)
		capi.mclBnGT_getStr = wrap_outputString(capi._mclBnGT_getStr)
		///////////////////////////////////////////////////////////////
		capi.bls_free = capi.mcl_free
		capi.blsId_malloc = capi.mclBnFr_malloc
		capi.blsSecretKey_malloc = capi.mclBnFr_malloc
		capi.blsPublicKey_malloc = capi.mclBnG2_malloc
		capi.blsSignature_malloc = capi.mclBnG1_malloc

		capi.blsInit = function(curveType = MCLBN_CURVE_FP254BNB) {
			return capi._blsInit(curveType, MCLBN_FP_UNIT_SIZE)
		}

		capi.blsGetCurveOrder = wrap_outputString(capi._blsGetCurveOrder)
		capi.blsGetFieldOrder = wrap_outputString(capi._blsGetFieldOrder)

		capi.blsIdSetDecStr = wrap_input(capi._blsIdSetDecStr, 1)
		capi.blsIdSetHexStr = wrap_input(capi._blsIdSetHexStr, 1)
		capi.blsIdGetDecStr = wrap_outputString(capi._blsIdGetDecStr)
		capi.blsIdGetHexStr = wrap_outputString(capi._blsIdGetHexStr)

		capi.blsSecretKeySetDecStr = wrap_input(capi._blsSecretKeySetDecStr, 1)
		capi.blsSecretKeySetHexStr = wrap_input(capi._blsSecretKeySetHexStr, 1)
		capi.blsSecretKeyGetDecStr = wrap_outputString(capi._blsSecretKeyGetDecStr)
		capi.blsSecretKeyGetHexStr = wrap_outputString(capi._blsSecretKeyGetHexStr)

		capi.blsIdSerialize = wrap_outputArray(capi._blsIdSerialize)
		capi.blsSecretKeySerialize = wrap_outputArray(capi._blsSecretKeySerialize)
		capi.blsPublicKeySerialize = wrap_outputArray(capi._blsPublicKeySerialize)
		capi.blsSignatureSerialize = wrap_outputArray(capi._blsSignatureSerialize)

		capi.blsIdDeserialize = wrap_input(capi._blsIdDeserialize, 1)
		capi.blsSecretKeyDeserialize = wrap_input(capi._blsSecretKeyDeserialize, 1)
		capi.blsPublicKeyDeserialize = wrap_input(capi._blsPublicKeyDeserialize, 1)
		capi.blsSignatureDeserialize = wrap_input(capi._blsSignatureDeserialize, 1)

		capi.blsSecretKeySetLittleEndian = wrap_input(capi._blsSecretKeySetLittleEndian, 1)
		capi.blsHashToSecretKey = wrap_input(capi._blsHashToSecretKey, 1)
		capi.blsSign = wrap_input(capi._blsSign, 2)
		capi.blsVerify = wrap_input(capi._blsVerify, 2, true)

		capi.blsSecretKeyShare = wrap_keyShare(capi._blsSecretKeyShare, BLS_SECRETKEY_SIZE)
		capi.blsPublicKeyShare = wrap_keyShare(capi._blsPublicKeyShare, BLS_PUBLICKEY_SIZE)
		capi.blsSecretKeyRecover = wrap_recover(capi._blsSecretKeyRecover, BLS_SECRETKEY_SIZE, BLS_ID_SIZE)
		capi.blsPublicKeyRecover = wrap_recover(capi._blsPublicKeyRecover, BLS_PUBLICKEY_SIZE, BLS_ID_SIZE)
		capi.blsSignatureRecover = wrap_recover(capi._blsSignatureRecover, BLS_SIGNATURE_SIZE, BLS_ID_SIZE)

		capi.sheInit = function(curveType = MCLBN_CURVE_FP254BNB) {
			let r = capi._sheInit(curveType, MCLBN_FP_UNIT_SIZE)
			console.log('sheInit ' + r)
			if (r) throw('sheInit')
		}
		class Common {
			constructor(size) {
				this.a_ = new Uint32Array(size / 4)
			}
			fromHexStr(s) {
				this.deserialize(self.fromHexStr(s))
			}
			toHexStr() {
				return self.toHexStr(this.serialize())
			}
			dump(msg = '') {
				console.log(msg + this.toHexStr())
			}
		}

		self.Id = class extends Common {
			constructor() {
				super(BLS_ID_SIZE)
			}
			setInt(x) {
				callSetter(capi.blsIdSetInt, this.a_, x)
			}
			setByCSPRNG() {
				callSetter(capi.blsSecretKeySetByCSPRNG, this.a_) // same type of BlsSecretKey
			}
			setStr(s, base = 10) {
				switch (base) {
				case 10:
					callSetter(capi.blsIdSetDecStr, this.a_, s)
					return
				case 16:
					callSetter(capi.blsIdSetHexStr, this.a_, s)
					return
				default:
					throw('BlsId.setStr:bad base:' + base)
				}
			}
			deserialize(s) {
				callSetter(capi.blsIdDeserialize, this.a_, s)
			}
			getStr(base = 10) {
				switch (base) {
				case 10:
					return callGetter(capi.blsIdGetDecStr, this.a_)
				case 16:
					return callGetter(capi.blsIdGetHexStr, this.a_)
				default:
					throw('BlsId.getStr:bad base:' + base)
				}
			}
			serialize() {
				return callGetter(capi.blsIdSerialize, this.a_)
			}
		}
		self.getIdFromHexStr = function(s) {
			r = new self.Id()
			r.fromHexStr(s)
			return r
		}

		self.SecretKey = class extends Common {
			constructor() {
				super(BLS_SECRETKEY_SIZE)
			}
			setInt(x) {
				callSetter(capi.blsIdSetInt, this.a_, x) // same as Id
			}
			deserialize(s) {
				callSetter(capi.blsSecretKeyDeserialize, this.a_, s)
			}
			setLittleEndian(s) {
				callSetter(capi.blsSecretKeySetLittleEndian, this.a_, s)
			}
			serialize() {
				return callGetter(capi.blsSecretKeySerialize, this.a_)
			}
			share(msk, id) {
				callShare(capi._blsSecretKeyShare, this.a_, BLS_SECRETKEY_SIZE, msk, id)
			}
			recover(secVec, idVec) {
				callRecover(capi._blsSecretKeyRecover, this.a_, BLS_SECRETKEY_SIZE, secVec, idVec)
			}
			setHashOf(s) {
				callSetter(capi.blsHashToSecretKey, this.a_, s)
			}
			setByCSPRNG() {
				let a = new Uint8Array(BLS_SECRETKEY_SIZE)
				crypto.getRandomValues(a)
				this.setLittleEndian(a)
		//		callSetter(capi.blsSecretKeySetByCSPRNG, this.a_)
			}
			getPublicKey() {
				let pub = new self.PublicKey()
				let stack = mod.Runtime.stackSave()
				let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
				let pubPos = mod.Runtime.stackAlloc(pub.a_.length * 4)
				mod.HEAP32.set(this.a_, secPos / 4)
				capi.blsGetPublicKey(pubPos, secPos)
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
			sign(m) {
				let sig = new self.Signature()
				let stack = mod.Runtime.stackSave()
				let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
				let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
				mod.HEAP32.set(this.a_, secPos / 4)
				capi.blsSign(sigPos, secPos, m)
				copyToUint32Array(sig.a_, sigPos)
				mod.Runtime.stackRestore(stack)
				return sig
			}
		}
		self.getSecretKeyFromHexStr = function(s) {
			r = new self.SecretKey()
			r.fromHexStr(s)
			return r
		}

		self.PublicKey = class extends Common {
			constructor() {
				super(BLS_PUBLICKEY_SIZE)
			}
			deserialize(s) {
				callSetter(capi.blsPublicKeyDeserialize, this.a_, s)
			}
			serialize() {
				return callGetter(capi.blsPublicKeySerialize, this.a_)
			}
			share(msk, id) {
				callShare(capi._blsPublicKeyShare, this.a_, BLS_PUBLICKEY_SIZE, msk, id)
			}
			recover(secVec, idVec) {
				callRecover(capi._blsPublicKeyRecover, this.a_, BLS_PUBLICKEY_SIZE, secVec, idVec)
			}
			verify(sig, m) {
				let stack = mod.Runtime.stackSave()
				let pubPos = mod.Runtime.stackAlloc(this.a_.length * 4)
				let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
				mod.HEAP32.set(this.a_, pubPos / 4)
				mod.HEAP32.set(sig.a_, sigPos / 4)
				let r = capi.blsVerify(sigPos, pubPos, m)
				mod.Runtime.stackRestore(stack)
				return r != 0
			}
		}
		self.getPublicKeyFromHexStr = function(s) {
			r = new self.PublicKey()
			r.fromHexStr(s)
			return r
		}

		self.Signature = class extends Common {
			constructor() {
				super(BLS_SIGNATURE_SIZE)
			}
			deserialize(s) {
				callSetter(capi.blsSignatureDeserialize, this.a_, s)
			}
			serialize() {
				return callGetter(capi.blsSignatureSerialize, this.a_)
			}
			recover(secVec, idVec) {
				callRecover(capi._blsSignatureRecover, this.a_, BLS_SIGNATURE_SIZE, secVec, idVec)
			}
		}
		self.getSignatureFromHexStr = function(s) {
			r = new self.Signature()
			r.fromHexStr(s)
			return r
		}
	}
	self.init = function(curveType = MCLBN_CURVE_FP254BNB, callback = null) {
		setupWasm('bls_c.wasm', null, function(_mod, ns) {
			mod = _mod
			fetch('exported-bls.json')
				.then(response => response.json())
				.then(json => {
					mod.json = json
					json.forEach(func => {
						capi[func.exportName] = mod.cwrap(func.name, func.returns, func.args)
					})
					define_extra_functions(mod)
					let r = capi.blsInit(curveType)
					console.log('finished ' + r)
					if (callback) callback()
				})
		})
	}
	return self
})
