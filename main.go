package main

import (
	"encoding/hex"
	"errors"
	"fmt"

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

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func log(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	fmt.Printf("\n")
}

func main() {
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

func walletConns() (*wallet, *wallet) {
	w1 := connectToWallet("localhost:19121", "/home/user/.config/decrediton/wallets/testnet/default-wallet/rpc.cert")
	w1.passphrase = []byte("123")
	log("Connected to wallet 1")

	w2 := connectToWallet("localhost:19221", "/home/user/.config/decrediton/wallets/testnet/new-testnet02/rpc.cert")
	w2.passphrase = []byte("123")
	log("Connected to wallet 2")

	return w1, w2
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

func signWithPair(priv1, priv2 *secp256k1.PrivateKey, msg []byte) *schnorr.Signature {
	extra := []byte(nil)
	version := schnorr.BlakeVersionStringRFC6979

	// Generate the nonce'd priv/pub keypair for each wallet
	spriv1, spub1, err := schnorr.GenerateNoncePair(curve, msg, priv1, extra, version)
	orPanic(err)

	spriv2, spub2, err := schnorr.GenerateNoncePair(curve, msg, priv2, extra, version)
	orPanic(err)

	// the wallets exchange their respective spub* to each other.

	// Generate a partial sig of the data on each wallet
	// (the combinedPub* are the pubkeys of the wallets other than the one
	// signing)
	combinedPub1 := schnorr.CombinePubkeys([]*secp256k1.PublicKey{spub2})
	sig1, err := schnorr.PartialSign(curve, msg, priv1, spriv1, combinedPub1)
	orPanic(err)

	combinedPub2 := schnorr.CombinePubkeys([]*secp256k1.PublicKey{spub1})
	sig2, err := schnorr.PartialSign(curve, msg, priv2, spriv2, combinedPub2)
	orPanic(err)

	// the wallets exchange their respective sig* to each other
	// any/all wallets may do this to create the full sig:

	fullSig, err := schnorr.CombineSigs(curve, []*schnorr.Signature{sig1, sig2})
	orPanic(err)

	pub1 := secp256k1.PublicKey(priv1.PublicKey)
	pub2 := secp256k1.PublicKey(priv2.PublicKey)

	// Wallets now share their respective pub* keys. They can now verify the
	// signature is correct each by doing the following:

	combinedPub := schnorr.CombinePubkeys([]*secp256k1.PublicKey{&pub1, &pub2})
	res := schnorr.Verify(combinedPub, msg, fullSig.R, fullSig.S)
	if !res {
		orPanic(errors.New("VERIFY FAILED!"))
	}

	return fullSig
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

	// wallets share their respective pubkeys

	combinedPub := schnorr.CombinePubkeys([]*secp256k1.PublicKey{&pub1, &pub2})
	addr, err := dcrutil.NewAddressSecSchnorrPubKey(combinedPub.Serialize(), net)
	orPanic(err)

	log("Generated schnorr addr: %s", addr.EncodeAddress())

	// each wallet generates the inputs and change output
	// they share those

	w1change, w1inputs, utxos1 := w1.genSrcTxData(addr)
	w2change, w2inputs, utxos2 := w2.genSrcTxData(addr)

	// the unsigned source tx can be created
	srcTx := makeSrcTx(w1change, w1inputs, w2change, w2inputs, addr)

	// each wallet signs their respective inputs (we create a copy to simulate
	// each wallet having a non-signed template )
	template := srcTx.Copy()
	w1.signSrcTx(template, srcTx, utxos2)
	w2.signSrcTx(template, srcTx, utxos1)

	// and the unsigned destination tx can be created as well
	dstTx := makeDstTx(dst1, dst2, srcTx)

	// get the data to sign the transaction
	hashToSign, err := txscript.CalcSignatureHash(srcTx.TxOut[0].PkScript,
		txscript.SigHashAll, dstTx, 0, nil)
	orPanic(err)

	// each wallet can now create its partial sig
	// the partial sigs are exchanged, and the final sig is assembled.
	fullSig := signWithPair(priv1, priv2, hashToSign)

	// and now we assemble the SigScript as a data push, so that the vm
	// will process it correctly. Note the append of sig type at the end.
	fullSigBytes := fullSig.Serialize()
	sigScript, err := txscript.NewScriptBuilder().
		AddData(append(fullSigBytes, byte(txscript.SigHashAll))).
		Script()
	orPanic(err)
	dstTx.TxIn[0].SignatureScript = sigScript

	// and now the network will do something like this to verify if the tx
	// is correctly signed
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

	dstTxBytes, err := dstTx.Bytes()
	orPanic(err)
	log("Dest tx")
	log(hex.EncodeToString(dstTxBytes))
}

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

	combinedPub := schnorr.CombinePubkeys(pubs)
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

	noncesToCombine := make([]*secp256k1.PublicKey, numKeys-1)
	for i := 0; i < numKeys; i++ {
		nidx := 0
		for j := 0; j < numKeys; j++ {
			if i == j {
				continue
			}
			noncesToCombine[nidx] = spubs[j]
			nidx++
		}

		combinedPartial := schnorr.CombinePubkeys(noncesToCombine)
		sig, err := schnorr.PartialSign(curve, hashToSign[:], privs[i],
			sprivs[i], combinedPartial)
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
