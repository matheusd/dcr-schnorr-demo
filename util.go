package main

import (
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
)

func wif2secpPrivKey(addr string) *secp256k1.PrivateKey {
	wif, err := dcrutil.DecodeWIF(addr)
	orPanic(err)

	if !wif.IsForNet(net) {
		orPanic(fmt.Errorf("not for the correct network"))
	}

	if wif.PrivKey.GetType() != chainec.ECTypeSecp256k1 {
		orPanic(fmt.Errorf("not the correct type of priv key"))
	}

	return secp256k1.NewPrivateKey(wif.PrivKey.GetD())
}

func srcAndDstFees(srcTx, dstTx *wire.MsgTx, utxos utxoMap) {
	srcInput := int64(0)
	for _, in := range srcTx.TxIn {
		oldOut, has := utxos[in.PreviousOutPoint]
		if !has {
			orPanic(fmt.Errorf("doesn't have outpoint %s", in.PreviousOutPoint))
		}

		srcInput += oldOut.Value
	}

	srcOutput := int64(0)
	for _, out := range srcTx.TxOut {
		srcOutput += out.Value
	}

	srcByteSize := srcTx.SerializeSize()
	srcFee := srcInput - srcOutput
	srcFeeRate := float64(srcFee) / float64(srcByteSize*1e5)

	dstOutput := int64(0)
	for _, out := range dstTx.TxOut {
		dstOutput += out.Value
	}

	dstByteSize := dstTx.SerializeSize()
	dstFee := srcTx.TxOut[0].Value - dstOutput
	dstFeeRate := float64(dstFee) / float64(dstByteSize*1e5)

	log("Source: %d bytes, %s fee, %.4f DCR/KB", srcByteSize,
		dcrutil.Amount(srcFee), srcFeeRate)
	log("Dest  : %d bytes, %s fee, %.4f DCR/KB", dstByteSize,
		dcrutil.Amount(dstFee), dstFeeRate)
}

func makeSrcTx(w1change *wire.TxOut, w1inputs []*wire.TxIn,
	w2change *wire.TxOut, w2inputs []*wire.TxIn, addr dcrutil.Address) *wire.MsgTx {

	tx := wire.NewMsgTx()
	for _, in := range w1inputs {
		tx.AddTxIn(in)
	}

	for _, in := range w2inputs {
		tx.AddTxIn(in)
	}

	payScript, err := txscript.PayToAddrScript(addr)
	orPanic(err)

	payOut := wire.NewTxOut(int64(wallet2SrcAmount), payScript)

	tx.AddTxOut(payOut)
	tx.AddTxOut(w1change)
	tx.AddTxOut(w2change)

	return tx
}

func makeDstTx(dst1, dst2 dcrutil.Address, srcTx *wire.MsgTx) *wire.MsgTx {

	srcHash := srcTx.TxHash()
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&srcHash, 0, 0), nil))

	payScript1, err := txscript.PayToAddrScript(dst1)
	orPanic(err)

	payScript2, err := txscript.PayToAddrScript(dst2)
	orPanic(err)

	value := int64(walletDstAmount)

	tx.AddTxOut(wire.NewTxOut(value, payScript1))
	tx.AddTxOut(wire.NewTxOut(value, payScript2))

	return tx
}

func makeSingleSrcTx(w1change *wire.TxOut, w1inputs []*wire.TxIn,
	addr dcrutil.Address) *wire.MsgTx {

	tx := wire.NewMsgTx()
	for _, in := range w1inputs {
		tx.AddTxIn(in)
	}

	// just for funsies :P
	opReturnData := []byte("Mah Schnorr! 6f04...af14")
	opReturnScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData(opReturnData).
		Script()
	orPanic(err)

	payScript, err := txscript.PayToAddrScript(addr)
	orPanic(err)

	payOut := wire.NewTxOut(int64(walletSrcAmount), payScript)

	tx.AddTxOut(payOut)
	tx.AddTxOut(w1change)
	tx.AddTxOut(wire.NewTxOut(0, opReturnScript))

	return tx
}

func makeSingleDstTx(destAddr dcrutil.Address, srcTx *wire.MsgTx) *wire.MsgTx {
	srcHash := srcTx.TxHash()
	tx := wire.NewMsgTx()
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&srcHash, 0, 0), nil))

	payScript, err := txscript.PayToAddrScript(destAddr)
	orPanic(err)

	tx.AddTxOut(wire.NewTxOut(int64(walletDstAmount), payScript))

	return tx
}
