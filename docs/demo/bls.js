(function(generator) {
  if (typeof exports === 'object') {
    const crypto = require('crypto')
    crypto.getRandomValues = crypto.randomFillSync
    exports.mod = require('./bls_c.js')
    generator(exports, crypto, true)
  } else {
    const crypto = window.crypto || window.msCrypto
    const exports = {}
    exports.mod = {}
    window.bls = generator(exports, crypto, false)
  }
})(function(exports, crypto, isNodeJs) {

  const MCLBN_CURVE_FP254BNB = 0
  const MCLBN_CURVE_FP382_1 = 1
  const MCLBN_CURVE_FP382_2 = 2

  const MCLBN_FP_UNIT_SIZE = 6

  const BLS_ID_SIZE = MCLBN_FP_UNIT_SIZE * 8
  const BLS_SECRETKEY_SIZE = BLS_ID_SIZE
  const BLS_PUBLICKEY_SIZE = BLS_ID_SIZE * 3 * 2
  const BLS_SIGNATURE_SIZE = BLS_ID_SIZE * 3

  const mod = exports.mod

  exports.init = (curveType = MCLBN_CURVE_FP254BNB) => {
    console.log('init')
    if (!isNodeJs) {
      fetch('bls_c.wasm')
        .then(response => response.arrayBuffer())
        .then(buffer => new Uint8Array(buffer))
        .then(binary => { Module(mod) })
    }
    return new Promise((resolve) => {
      mod.onRuntimeInitialized = () => {
        define_extra_functions(mod)
        exports.blsInit(curveType)
        console.log('finished')
        resolve()
      }
    })
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
    a.set(mod.HEAP32.subarray(pos / 4, pos / 4 + a.length))
//    for (let i = 0; i < a.length; i++) {
//      a[i] = mod.HEAP32[pos / 4 + i]
//    }
  }
  const copyFromUint32Array = function(pos, a) {
    for (let i = 0; i < a.length; i++) {
      mod.HEAP32[pos / 4 + i] = a[i]
    }
  }
  exports.toHex = function(a, start, n) {
    let s = ''
    for (let i = 0; i < n; i++) {
      s += ('0' + a[start + i].toString(16)).slice(-2)
    }
    return s
  }
  // Uint8Array to hex string
  exports.toHexStr = function(a) {
    return exports.toHex(a, 0, a.length)
  }
  // hex string to Uint8Array
  exports.fromHexStr = function(s) {
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
    // change curveType
    exports.blsInit = function(curveType = MCLBN_CURVE_FP254BNB) {
      const r = mod._blsInit(curveType, MCLBN_FP_UNIT_SIZE)
      if (r) throw('blsInit err ' + r)
    }

    exports.getCurveOrder = wrap_outputString(mod._blsGetCurveOrder)
    exports.getFieldOrder = wrap_outputString(mod._blsGetFieldOrder)

    mod.blsIdSetDecStr = wrap_input(mod._blsIdSetDecStr, 1)
    mod.blsIdSetHexStr = wrap_input(mod._blsIdSetHexStr, 1)
    mod.blsIdGetDecStr = wrap_outputString(mod._blsIdGetDecStr)
    mod.blsIdGetHexStr = wrap_outputString(mod._blsIdGetHexStr)

    mod.blsIdSerialize = wrap_outputArray(mod._blsIdSerialize)
    mod.blsSecretKeySerialize = wrap_outputArray(mod._blsSecretKeySerialize)
    mod.blsPublicKeySerialize = wrap_outputArray(mod._blsPublicKeySerialize)
    mod.blsSignatureSerialize = wrap_outputArray(mod._blsSignatureSerialize)

    mod.blsIdDeserialize = wrap_input(mod._blsIdDeserialize, 1)
    mod.blsSecretKeyDeserialize = wrap_input(mod._blsSecretKeyDeserialize, 1)
    mod.blsPublicKeyDeserialize = wrap_input(mod._blsPublicKeyDeserialize, 1)
    mod.blsSignatureDeserialize = wrap_input(mod._blsSignatureDeserialize, 1)

    mod.blsSecretKeySetLittleEndian = wrap_input(mod._blsSecretKeySetLittleEndian, 1)
    mod.blsHashToSecretKey = wrap_input(mod._blsHashToSecretKey, 1)
    mod.blsSign = wrap_input(mod._blsSign, 2)
    mod.blsVerify = wrap_input(mod._blsVerify, 2, true)

    class Common {
      constructor(size) {
        this.a_ = new Uint32Array(size / 4)
      }
      fromHexStr(s) {
        this.deserialize(exports.fromHexStr(s))
      }
      toHexStr() {
        return exports.toHexStr(this.serialize())
      }
      dump(msg = '') {
        console.log(msg + this.toHexStr())
      }
    }

    exports.Id = class extends Common {
      constructor() {
        super(BLS_ID_SIZE)
      }
      setInt(x) {
        callSetter(mod._blsIdSetInt, this.a_, x)
      }
      deserialize(s) {
        callSetter(mod.blsIdDeserialize, this.a_, s)
      }
      serialize() {
        return callGetter(mod.blsIdSerialize, this.a_)
      }
      setStr(s, base = 10) {
        switch (base) {
        case 10:
          callSetter(mod.blsIdSetDecStr, this.a_, s)
          return
        case 16:
          callSetter(mod.blsIdSetHexStr, this.a_, s)
          return
        default:
          throw('BlsId.setStr:bad base:' + base)
        }
      }
      getStr(base = 10) {
        switch (base) {
        case 10:
          return callGetter(mod.blsIdGetDecStr, this.a_)
        case 16:
          return callGetter(mod.blsIdGetHexStr, this.a_)
        default:
          throw('BlsId.getStr:bad base:' + base)
        }
      }
      setLittleEndian(s) {
        callSetter(mod.blsSecretKeySetLittleEndian, this.a_, s)
      }
      setByCSPRNG() {
        let a = new Uint8Array(BLS_ID_SIZE)
        crypto.getRandomValues(a)
        this.setLittleEndian(a)
      }
    }
    exports.getIdFromHexStr = function(s) {
      r = new exports.Id()
      r.fromHexStr(s)
      return r
    }

    exports.SecretKey = class extends Common {
      constructor() {
        super(BLS_SECRETKEY_SIZE)
      }
      setInt(x) {
        callSetter(mod._blsIdSetInt, this.a_, x) // same as Id
      }
      deserialize(s) {
        callSetter(mod.blsSecretKeyDeserialize, this.a_, s)
      }
      serialize() {
        return callGetter(mod.blsSecretKeySerialize, this.a_)
      }
      share(msk, id) {
        callShare(mod._blsSecretKeyShare, this.a_, BLS_SECRETKEY_SIZE, msk, id)
      }
      recover(secVec, idVec) {
        callRecover(mod._blsSecretKeyRecover, this.a_, BLS_SECRETKEY_SIZE, secVec, idVec)
      }
      setHashOf(s) {
        callSetter(mod.blsHashToSecretKey, this.a_, s)
      }
      setLittleEndian(s) {
        callSetter(mod.blsSecretKeySetLittleEndian, this.a_, s)
      }
      setByCSPRNG() {
        let a = new Uint8Array(BLS_SECRETKEY_SIZE)
        crypto.getRandomValues(a)
        this.setLittleEndian(a)
    //    callSetter(mod._blsSecretKeySetByCSPRNG, this.a_)
      }
      getPublicKey() {
        let pub = new exports.PublicKey()
        let stack = mod.Runtime.stackSave()
        let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
        let pubPos = mod.Runtime.stackAlloc(pub.a_.length * 4)
        mod.HEAP32.set(this.a_, secPos / 4)
        mod._blsGetPublicKey(pubPos, secPos)
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
        let sig = new exports.Signature()
        let stack = mod.Runtime.stackSave()
        let secPos = mod.Runtime.stackAlloc(this.a_.length * 4)
        let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
        mod.HEAP32.set(this.a_, secPos / 4)
        mod.blsSign(sigPos, secPos, m)
        copyToUint32Array(sig.a_, sigPos)
        mod.Runtime.stackRestore(stack)
        return sig
      }
    }
    exports.getSecretKeyFromHexStr = function(s) {
      r = new exports.SecretKey()
      r.fromHexStr(s)
      return r
    }

    exports.PublicKey = class extends Common {
      constructor() {
        super(BLS_PUBLICKEY_SIZE)
      }
      deserialize(s) {
        callSetter(mod.blsPublicKeyDeserialize, this.a_, s)
      }
      serialize() {
        return callGetter(mod.blsPublicKeySerialize, this.a_)
      }
      share(msk, id) {
        callShare(mod._blsPublicKeyShare, this.a_, BLS_PUBLICKEY_SIZE, msk, id)
      }
      recover(secVec, idVec) {
        callRecover(mod._blsPublicKeyRecover, this.a_, BLS_PUBLICKEY_SIZE, secVec, idVec)
      }
      verify(sig, m) {
        let stack = mod.Runtime.stackSave()
        let pubPos = mod.Runtime.stackAlloc(this.a_.length * 4)
        let sigPos = mod.Runtime.stackAlloc(sig.a_.length * 4)
        mod.HEAP32.set(this.a_, pubPos / 4)
        mod.HEAP32.set(sig.a_, sigPos / 4)
        let r = mod.blsVerify(sigPos, pubPos, m)
        mod.Runtime.stackRestore(stack)
        return r != 0
      }
    }
    exports.getPublicKeyFromHexStr = function(s) {
      r = new exports.PublicKey()
      r.fromHexStr(s)
      return r
    }

    exports.Signature = class extends Common {
      constructor() {
        super(BLS_SIGNATURE_SIZE)
      }
      deserialize(s) {
        callSetter(mod.blsSignatureDeserialize, this.a_, s)
      }
      serialize() {
        return callGetter(mod.blsSignatureSerialize, this.a_)
      }
      recover(secVec, idVec) {
        callRecover(mod._blsSignatureRecover, this.a_, BLS_SIGNATURE_SIZE, secVec, idVec)
      }
    }
    exports.getSignatureFromHexStr = function(s) {
      r = new exports.Signature()
      r.fromHexStr(s)
      return r
    }
  }
  return exports
})
