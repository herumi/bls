function getValue(name) { return document.getElementsByName(name)[0].value }
function setValue(name, val) { document.getElementsByName(name)[0].value = val }
function getText(name) { return document.getElementsByName(name)[0].innerText }
function setText(name, val) { document.getElementsByName(name)[0].innerText = val }

bls.init()
  .then(() => {
    setText('status', 'ok')
    setText('curveOrder', bls.getCurveOrder())
  })

let prevSelectedCurve = -1
function onChangeSelectCurve() {
	const obj = document.selectCurve.curveType
	const idx = obj.selectedIndex
	const curve = obj.options[idx].value
	if (curve == prevSelectedCurve) return
	prevSelectedCurve = curve
	console.log('idx=' + idx)
	const r = bls.blsInit(idx)
	setText('status', r ? 'err:' + r : 'ok')
	setText('curveOrder', bls.getCurveOrder())
}

function rand(val) {
	const x = new she.Id()
	x.setByCSPRNG()
	setValue(val, c.toHexStr())
}

function bench(label, count, func) {
	const start = Date.now()
	for (let i = 0; i < count; i++) {
		func()
	}
	const end = Date.now()
	const t = (end - start) / count
	setText(label, t)
}

function benchBls() {
	const sec = new bls.SecretKey()
	sec.setByCSPRNG()
	const pub = sec.getPublicKey()
	const msg = 'abc'
	bench('time_sign_class', 50, () => sec.sign(msg))
	const sig = sec.sign(msg)
	bench('time_verify_class', 50, () => pub.verify(sig, msg))
}
function onClickBenchmark() {
	benchBls()
}

function onClickTestSignature() {
	const sec = new bls.SecretKey()

	sec.setByCSPRNG()
	setText('secretKey', sec.toHexStr())

	const pub = sec.getPublicKey()
	setText('publicKey', pub.toHexStr())

	const msg = getValue('msg')
	console.log('msg=' + msg)
	const sig = sec.sign(msg)
	setText('signature', sig.toHexStr())

	const r = pub.verify(sig, msg)
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
	const idDec = getValue('idDec')
	console.log('idDec=' + idDec)
	const id = new bls.Id()
	id.setStr(idDec)
	setText('idDec2', id.getStr())
	setText('idHex', id.getStr(16))
	const sec = new bls.SecretKey()
	sec.setLittleEndian(bls.fromHexStr(getValue('sec1')))
	setText('secSerialize', sec.toHexStr())
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
