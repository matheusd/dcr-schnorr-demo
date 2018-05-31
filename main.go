package main

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/txscript"

	"github.com/decred/dcrd/dcrec/secp256k1/schnorr"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1"
)

var (
	net        = &chaincfg.TestNet2Params
	curve      = secp256k1.S256()
	srcAccount = 0
	sampleMsg  = []byte("Yipie khay ey lumber knuckler :)")

	srcTxFeePad, _      = dcrutil.NewAmount(0.0003) // a little bit extra fee on the src tx
	walletSrcAmount, _  = dcrutil.NewAmount(0.1004) // what each wallet inputs
	wallet2SrcAmount, _ = dcrutil.NewAmount(0.2008) // two times the above
	walletDstAmount, _  = dcrutil.NewAmount(0.1)    // what each wallet gets back

	// protocol is which set of functions (which particular schnorr protocol) to
	// use when signing messages/transactions
	protocol schnorrProtocol = originalDcrSchnorrProtocol{}

	currentScriptFlags = txscript.ScriptBip16 |
		txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyDERSignatures |
		txscript.ScriptVerifyStrictEncoding |
		txscript.ScriptVerifyMinimalData |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifySHA256
)

// walletConns connects to two standard wallets.
func walletConns() (*wallet, *wallet) {
	w1 := connectToWallet("localhost:19121", "/home/user/.config/decrediton/wallets/testnet/default-wallet/rpc.cert")
	w1.passphrase = []byte("123")
	log("Connected to wallet 1")

	w2 := connectToWallet("localhost:19221", "/home/user/.config/decrediton/wallets/testnet/new-testnet02/rpc.cert")
	w2.passphrase = []byte("123")
	log("Connected to wallet 2")

	return w1, w2
}

func main() {
	// choose which test(s) you want to run by commenting/uncommenting the lines.
	// mainRandomKeys()
	// mainWalletKeys()
	// mainTx()
	mainTxSingle()
}

// test signging with randomly generated keys
func mainRandomKeys() {
	priv1, err := secp256k1.GeneratePrivateKey()
	orPanic(err)

	priv2, err := secp256k1.GeneratePrivateKey()
	orPanic(err)

	signWithPair(priv1, priv2, sampleMsg)
	log("Testing with random keys worked")
}

// test signing with wallet generated keys
func mainWalletKeys() {
	w1, w2 := walletConns()

	pkh1, pk1 := w1.nextAddress()
	log("Addr for wallet 1: %s | %s", pkh1, pk1)

	pkh2, pk2 := w2.nextAddress()
	log("Addr for wallet 2: %s | %s", pkh2, pk2)

	priv1 := wif2secpPrivKey(w1.privateKey(pkh1))
	priv2 := wif2secpPrivKey(w2.privateKey(pkh2))

	signWithPair(priv1, priv2, sampleMsg)
	log("Testing with wallet keys worked")
}

func mainTx() {
	w1, w2 := walletConns()

	// each wallet generates addresses (these could have been random)

	pkh1, _ := w1.nextAddress()
	priv1 := wif2secpPrivKey(w1.privateKey(pkh1))
	pub1 := secp256k1.PublicKey(priv1.PublicKey)
	dst1, _ := w1.nextAddress()

	pkh2, _ := w2.nextAddress()
	priv2 := wif2secpPrivKey(w2.privateKey(pkh2))
	pub2 := secp256k1.PublicKey(priv2.PublicKey)
	dst2, _ := w2.nextAddress()

	allPubs := []*secp256k1.PublicKey{&pub1, &pub2}

	// wallets share their respective pubkeys

	combinedPub, err := protocol.combinePubKeys(allPubs)
	orPanic(err)
	addr, err := dcrutil.NewAddressSecSchnorrPubKey(combinedPub.Serialize(), net)
	orPanic(err)

	log("Generated schnorr addr: %s", addr.EncodeAddress())

	// Each wallet generates the inputs and change output.
	// They share those.

	w1change, w1inputs, utxos1 := w1.genSrcTxData(addr)
	w2change, w2inputs, utxos2 := w2.genSrcTxData(addr)

	// The unsigned source tx, which aggregates inputs from both wallets into
	// a single destination output can be created.
	srcTx := makeSrcTx(w1change, w1inputs, w2change, w2inputs, addr)

	// Each wallet signs their respective inputs (we create a copy to simulate
	// each wallet having a non-signed template, with srcTx getting all
	// signatures). In practice, the signatures would have to be shared among
	// the wallets so that each could build the final signed srcTx.
	template := srcTx.Copy()
	w1.signSrcTx(template, srcTx, utxos2)
	w2.signSrcTx(template, srcTx, utxos1)

	// The unsigned destination tx can now be created. This is the tx that
	// spends from the combined output of the srcTx.
	dstTx := makeDstTx(dst1, dst2, srcTx)

	// Get the data to sign the redeem transaction. Remember that
	// srcTx.TxOut[0] is the output that can be redeemed with a schnorr
	// signature.
	hashToSign, err := txscript.CalcSignatureHash(srcTx.TxOut[0].PkScript,
		txscript.SigHashAll, dstTx, 0, nil)
	orPanic(err)

	// Each wallet can now create its partial sig.
	// The partial sigs are exchanged, and the final sig is assembled.
	fullSig := signWithPair(priv1, priv2, hashToSign)

	// Now we assemble the SigScript as a data push, so that the vm
	// will process it correctly. Note the append of sig type at the end.
	fullSigBytes := fullSig.Serialize()
	sigScript, err := txscript.NewScriptBuilder().
		AddData(append(fullSigBytes, byte(txscript.SigHashAll))).
		Script()
	orPanic(err)
	dstTx.TxIn[0].SignatureScript = sigScript

	// At this point, dstTx is signed and finalized and can be published to
	// the network, where it will be mined (assuming srcTx has been previously
	// published and mined as well).

	// The network will do something like this to verify if the input of the
	// dstTx is correctly signed (remember that dstTx.TxIn[0] is redeeming
	// srcTx.TxOut[0]).
	vm, err := txscript.NewEngine(srcTx.TxOut[0].PkScript, dstTx, 0,
		currentScriptFlags, srcTx.TxOut[0].Version, nil)
	orPanic(err)

	err = vm.Execute()
	orPanic(err)

	// If execution didn't panic so far, it means the verification of the schnorr
	// signature passed. Woohoo!
	// Let's output the final txs, so we can actually test broadcasting them via
	// dcrd or dcrdata.
	srcTxBytes, err := srcTx.Bytes()
	orPanic(err)
	log("Source tx")
	log(hex.EncodeToString(srcTxBytes))

	dstTxBytes, err := dstTx.Bytes()
	orPanic(err)
	log("Dest tx")
	log(hex.EncodeToString(dstTxBytes))
}

// This will simulate making a schnorr sig tx but using only a single wallet
// and a *big* number of partial sigs. The process is similar to the one for
// two wallets (so look at the comments there), except we're being silly
// and simulating as if there was a very large number of wallets involved in the
// partial sig.
func mainTxSingle() {
	w1 := connectToWallet("localhost:19121", "/home/user/.config/decrediton/wallets/testnet/default-wallet/rpc.cert")
	w1.passphrase = []byte("123")
	log("Connected to wallet 1")

	dstAddr, _ := w1.nextAddress()
	numKeys := 150 // wowzers!
	extra := []byte(nil)
	version := schnorr.BlakeVersionStringRFC6979

	privs := make([]*secp256k1.PrivateKey, numKeys)
	pubs := make([]*secp256k1.PublicKey, numKeys)
	sprivs := make([]*secp256k1.PrivateKey, numKeys)
	spubs := make([]*secp256k1.PublicKey, numKeys)
	partialSigs := make([]*schnorr.Signature, numKeys)

	for i := 0; i < numKeys; i++ {
		priv, err := secp256k1.GeneratePrivateKey()
		orPanic(err)

		pub := secp256k1.PublicKey(priv.PublicKey)

		privs[i] = priv
		pubs[i] = &pub
	}

	combinedPub, err := protocol.combinePubKeys(pubs)
	orPanic(err)
	addr, err := dcrutil.NewAddressSecSchnorrPubKey(combinedPub.Serialize(), net)
	orPanic(err)
	log("Generated schnorr addr: %s", addr.EncodeAddress())

	w1change, w1inputs, utxos := w1.genSrcTxData(addr)
	srcTx := makeSingleSrcTx(w1change, w1inputs, addr)

	w1.signSrcTx(srcTx.Copy(), srcTx, nil)

	dstTx := makeSingleDstTx(dstAddr, srcTx)

	hashToSign, err := txscript.CalcSignatureHash(srcTx.TxOut[0].PkScript,
		txscript.SigHashAll, dstTx, 0, nil)
	orPanic(err)

	for i := 0; i < numKeys; i++ {
		spriv, spub, err := schnorr.GenerateNoncePair(curve, hashToSign[:],
			privs[i], extra, version)
		orPanic(err)
		sprivs[i] = spriv
		spubs[i] = spub
	}

	for i := 0; i < numKeys; i++ {
		sig, err := protocol.partialSign(hashToSign[:], privs[i], sprivs[i],
			pubs[i], spubs[i], pubs, spubs)
		orPanic(err)
		partialSigs[i] = sig
	}

	fullSig, err := schnorr.CombineSigs(curve, partialSigs)
	orPanic(err)

	fullSigBytes := fullSig.Serialize()
	sigScript, err := txscript.NewScriptBuilder().
		AddData(append(fullSigBytes, byte(txscript.SigHashAll))).
		Script()
	orPanic(err)
	dstTx.TxIn[0].SignatureScript = sigScript

	vm, err := txscript.NewEngine(srcTx.TxOut[0].PkScript, dstTx, 0,
		currentScriptFlags, srcTx.TxOut[0].Version, nil)
	orPanic(err)

	err = vm.Execute()
	orPanic(err)

	// all done! Publish them to see magic!
	srcTxBytes, err := srcTx.Bytes()
	orPanic(err)
	log("Source tx")
	log(hex.EncodeToString(srcTxBytes))
	log("")

	dstTxBytes, err := dstTx.Bytes()
	orPanic(err)
	log("Dest tx")
	log(hex.EncodeToString(dstTxBytes))
	log("")

	srcAndDstFees(srcTx, dstTx, utxos)
}
