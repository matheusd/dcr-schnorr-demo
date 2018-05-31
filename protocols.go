package main

import (
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrec/secp256k1/schnorr"
)

// schnorrProtocol stablishes the operations needed to simulate a multi-signature
// schnorr protocol on a local node.
type schnorrProtocol interface {
	// combinePubKeys must return an aggregated public key, given an array of
	// public keys (**NOT** public nonces) for participants
	combinePubKeys([]*secp256k1.PublicKey) (*secp256k1.PublicKey, error)

	// partialSign performs an individual sign operation on a local node. This
	// requires the private and public keys and nonces of a local node plus all
	// the public keys and nonces of all nodes. The order of the public key
	// and nonces must be well defined.
	partialSign(msg []byte,
		privKey *secp256k1.PrivateKey, privNonce *secp256k1.PrivateKey,
		pubKey *secp256k1.PublicKey, pubNonce *secp256k1.PublicKey,
		allPubKeys []*secp256k1.PublicKey, allPubNonces []*secp256k1.PublicKey) (*schnorr.Signature, error)
}

// originalDcrSchnorrProtocol fulfills the schnorrProtocol interface. It does so
// by using the original functions (combinePubKeys, partialSign) exported by
// the schnorr package of decred.
type originalDcrSchnorrProtocol struct{}

func (p originalDcrSchnorrProtocol) combinePubKeys(pubs []*secp256k1.PublicKey) (*secp256k1.PublicKey, error) {
	return schnorr.CombinePubkeys(pubs), nil
}

func (p originalDcrSchnorrProtocol) partialSign(msg []byte,
	privKey *secp256k1.PrivateKey, privNonce *secp256k1.PrivateKey,
	pubKey *secp256k1.PublicKey, pubNonce *secp256k1.PublicKey,
	allPubKeys []*secp256k1.PublicKey, allPubNonces []*secp256k1.PublicKey) (*schnorr.Signature, error) {

	// the original decred functions, as exemplified in the threshold_test.go
	// file, call for a partial signature that combines all public nonces, except
	// the one from the local node.
	// Therefore, we need to create a new slice, taking care to exclude the local
	// nonce pointed in pubNonce.

	pubsToCombine := make([]*secp256k1.PublicKey, 0, len(allPubNonces)-1)
	for _, pub := range allPubNonces {
		if pub.IsEqual(pubNonce) {
			continue
		}
		pubsToCombine = append(pubsToCombine, pub)
	}

	combinedPubs := schnorr.CombinePubkeys(pubsToCombine)
	return schnorr.PartialSign(curve, msg, privKey, privNonce, combinedPubs)
}

// naiveSchnorrProtocol fulfills the schnorrProtocol interface. It does so by
// using the naive schnorr protocol
type naiveSchnorrProtocol struct{}

// signWithPair is a helper function that simulates the current schnorr protocol
// (the global `protocol` var) with 2 private keys.
func signWithPair(priv1, priv2 *secp256k1.PrivateKey, msg []byte) *schnorr.Signature {
	extra := []byte(nil)
	version := schnorr.BlakeVersionStringRFC6979

	ppub1 := secp256k1.PublicKey(priv1.PublicKey)
	ppub2 := secp256k1.PublicKey(priv2.PublicKey)
	pub1 := &ppub1
	pub2 := &ppub2

	// Generate the nonce'd priv/pub keypair for each wallet
	privNonce1, pubNonce1, err := schnorr.GenerateNoncePair(curve, msg, priv1, extra, version)
	orPanic(err)

	privNonce2, pubNonce2, err := schnorr.GenerateNoncePair(curve, msg, priv2, extra, version)
	orPanic(err)

	// the wallets exchange their respective pub* and pubNonce* to each other.
	// this is done with a two-round protocol where hash(pub), hash(pubNonce)
	// is first shared, and then on a second step the actual pub/pubNonce is
	// shared and checked (on each node) against the previous hash. This is done
	// to prevent rogue key attacks.

	allPubs := []*secp256k1.PublicKey{pub1, pub2}
	allPubNonces := []*secp256k1.PublicKey{pubNonce1, pubNonce2}

	// Generate a partial sig of the data on each wallet
	// (the combinedPub* are the pubkeys of the wallets other than the one
	// signing)
	sig1, err := protocol.partialSign(msg, priv1, privNonce1, pub1, pubNonce1, allPubs, allPubNonces)
	orPanic(err)

	sig2, err := protocol.partialSign(msg, priv2, privNonce2, pub2, pubNonce2, allPubs, allPubNonces)
	orPanic(err)

	// the wallets exchange their respective sig* to each other
	// any/all wallets may do this to create the full sig:

	fullSig, err := schnorr.CombineSigs(curve, []*schnorr.Signature{sig1, sig2})
	orPanic(err)

	// Wallets can now verify that the signature is correct

	combinedPub := schnorr.CombinePubkeys([]*secp256k1.PublicKey{pub1, pub2})
	res := schnorr.Verify(combinedPub, msg, fullSig.R, fullSig.S)
	if !res {
		orPanic(errors.New("VERIFY FAILED!"))
	}

	return fullSig
}
