package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type utxoMap map[wire.OutPoint]*wire.TxOut

type wallet struct {
	wsvc       pb.WalletServiceClient
	conn       *grpc.ClientConn
	passphrase []byte
}

func connectToWallet(walletHost string, walletCert string) *wallet {
	rand.Seed(time.Now().Unix())
	creds, err := credentials.NewClientTLSFromFile(walletCert, "localhost")
	orPanic(err)

	conn, err := grpc.Dial(walletHost, grpc.WithTransportCredentials(creds))
	orPanic(err)

	wsvc := pb.NewWalletServiceClient(conn)

	resp, err := wsvc.Network(context.Background(), &pb.NetworkRequest{})
	if resp.ActiveNetwork != uint32(net.Net) {
		panic("wrong network")
	}

	w := &wallet{
		conn: conn,
		wsvc: wsvc,
	}

	return w
}

func (w *wallet) nextAddress() (dcrutil.Address, dcrutil.Address) {
	req := &pb.NextAddressRequest{
		Account:   uint32(srcAccount),
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
		Kind:      pb.NextAddressRequest_BIP0044_EXTERNAL,
	}
	res, err := w.wsvc.NextAddress(context.Background(), req)
	orPanic(err)

	pkh, err := dcrutil.DecodeAddress(res.Address)
	orPanic(err)

	pk, err := dcrutil.DecodeAddress(res.PublicKey)
	orPanic(err)

	return pkh, pk
}

func (w *wallet) privateKey(addr dcrutil.Address) string {
	req := &pb.GetPrivateKeyRequest{
		Address:    addr.String(),
		Passphrase: w.passphrase,
	}

	resp, err := w.wsvc.GetPrivateKey(context.Background(), req)
	orPanic(err)

	return resp.PrivateKey
}

func (w *wallet) genSrcTxData(destAddr dcrutil.Address) (*wire.TxOut, []*wire.TxIn, utxoMap) {
	amount := int64(walletSrcAmount + srcTxFeePad)
	output := &pb.ConstructTransactionRequest_Output{
		Amount: amount,
		Destination: &pb.ConstructTransactionRequest_OutputDestination{
			Address: destAddr.EncodeAddress(),
		},
	}
	outputs := []*pb.ConstructTransactionRequest_Output{output}

	req := &pb.ConstructTransactionRequest{
		FeePerKb:              0,
		RequiredConfirmations: 1,
		SourceAccount:         uint32(srcAccount),
		NonChangeOutputs:      outputs,
	}

	resp, err := w.wsvc.ConstructTransaction(context.Background(), req)
	orPanic(err)

	tx := wire.NewMsgTx()
	err = tx.FromBytes(resp.UnsignedTransaction)
	orPanic(err)

	if len(tx.TxOut) != 2 {
		orPanic(fmt.Errorf("len(txOut) != 2"))
	}

	utxos := make(utxoMap, len(tx.TxIn))
	for _, in := range tx.TxIn {
		reqtx := &pb.GetTransactionRequest{
			TransactionHash: in.PreviousOutPoint.Hash[:],
		}
		resptx, err := w.wsvc.GetTransaction(context.Background(), reqtx)
		orPanic(err)

		oldTx := wire.NewMsgTx()
		err = oldTx.FromBytes(resptx.Transaction.Transaction)
		orPanic(err)

		oldOut := oldTx.TxOut[in.PreviousOutPoint.Index]
		utxos[in.PreviousOutPoint] = oldOut
	}

	// not a great way to check which is the change and which is the real output
	// but fine for a poc
	if tx.TxOut[0].Value == amount {
		return tx.TxOut[1], tx.TxIn, utxos
	} else {
		return tx.TxOut[0], tx.TxIn, utxos
	}

}

func (w *wallet) signSrcTx(template, tx *wire.MsgTx, otherUtxos utxoMap) {
	srcBytes, err := template.Bytes()
	orPanic(err)

	addScripts := make([]*pb.SignTransactionRequest_AdditionalScript, len(otherUtxos))
	i := 0
	for outp, oldOut := range otherUtxos {
		addScripts[i] = &pb.SignTransactionRequest_AdditionalScript{
			PkScript:        oldOut.PkScript,
			OutputIndex:     outp.Index,
			Tree:            int32(outp.Tree),
			TransactionHash: outp.Hash[:],
		}
		i++
	}

	req := &pb.SignTransactionRequest{
		SerializedTransaction: srcBytes,
		Passphrase:            w.passphrase,
		AdditionalScripts:     addScripts,
	}

	resp, err := w.wsvc.SignTransaction(context.Background(), req)
	orPanic(err)

	signed := wire.NewMsgTx()
	err = signed.FromBytes(resp.Transaction)
	orPanic(err)

	for i, in := range signed.TxIn {
		if len(in.SignatureScript) == 0 {
			continue
		}
		tx.TxIn[i].SignatureScript = in.SignatureScript
	}
}
