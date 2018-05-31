package main

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrec/secp256k1/schnorr"
)

func combinePubkeysMusig(pks []*secp256k1.PublicKey) *secp256k1.PublicKey {
	numPubKeys := len(pks)

	// Have to have at least two pubkeys.
	if numPubKeys < 1 {
		return nil
	}
	if numPubKeys == 1 {
		return pks[0]
	}
	if pks[0] == nil || pks[1] == nil {
		return nil
	}

	hashFunc := chainhash.HashB

	L := hashPubKeysMusig(pks, hashFunc)
	// TODO: check L for == 0 and >= curve.N

	pkSumX := new(big.Int)
	pkSumY := new(big.Int)

	hashInput := make([]byte, 0, 32+33) // scalarsize + compress size

	for _, pub := range pks {
		pubSer := pub.Serialize()

		hashInput = hashInput[:0]
		hashInput = append(hashInput, L...)
		hashInput = append(hashInput, pubSer...)
		h := hashFunc(hashInput)

		// TODO: check hashInput for == 0 and >= curve.N
		partPubX, partPubY := curve.ScalarMult(pub.GetX(), pub.GetY(), h)
		pkSumX, pkSumY = curve.Add(pkSumX, pkSumY, partPubX, partPubY)
	}

	if !curve.IsOnCurve(pkSumX, pkSumY) {
		return nil
	}

	return secp256k1.NewPublicKey(pkSumX, pkSumY)
}

func partialSignMusig(curve *secp256k1.KoblitzCurve, msg []byte,
	priv *secp256k1.PrivateKey, privNonce *secp256k1.PrivateKey,
	pubNonceSum *secp256k1.PublicKey, pubKeys []*secp256k1.PublicKey) (*schnorr.Signature, error) {

	// this is global stuff in the schnorr module, copied locally here
	scalarSize := 32
	zeroSlice := func(s []byte) {
		for i := 0; i < scalarSize; i++ {
			s[i] = 0x00
		}
	}

	privBytes := priv.Serialize()
	defer zeroSlice(privBytes)
	privNonceBytes := privNonce.Serialize()
	defer zeroSlice(privNonceBytes)

	return schnorrPartialSignMusig(curve, msg, privBytes, privNonceBytes,
		pubNonceSum, pubKeys, chainhash.HashB)
}

func schnorrPartialSignMusig(curve *secp256k1.KoblitzCurve, msg []byte, priv []byte,
	privNonce []byte, pubNonceSum *secp256k1.PublicKey, pubKeys []*secp256k1.PublicKey,
	hashFunc func([]byte) []byte) (*schnorr.Signature, error) {

	// this is global stuff in the schnorr module, copied locally here
	scalarSize := 32
	bigZero := new(big.Int).SetInt64(0)
	schnorrError := func(c schnorr.ErrorCode, desc string) error {
		return schnorr.Error{c, desc}
	}

	// Sanity checks.
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if len(priv) != scalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(priv), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if len(privNonce) != scalarSize {
		str := fmt.Sprintf("wrong size for privnonce (got %v, want %v)",
			len(privNonce), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if pubNonceSum == nil {
		str := fmt.Sprintf("nil pubkey")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}

	privBig := new(big.Int).SetBytes(priv)
	if privBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("priv scalar is zero")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if privBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("priv scalar is out of bounds")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	privBig.SetInt64(0)

	privNonceBig := new(big.Int).SetBytes(privNonce)
	if privNonceBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("privNonce scalar is zero")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if privNonceBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("privNonce scalar is out of bounds")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	privNonceBig.SetInt64(0)

	if !curve.IsOnCurve(pubNonceSum.GetX(), pubNonceSum.GetY()) {
		str := fmt.Sprintf("public key sum is off curve")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}

	pubKeysHash := hashPubKeysMusig(pubKeys, hashFunc)

	return schnorrSignMusig(msg, priv, privNonce, pubNonceSum.GetX(),
		pubNonceSum.GetY(), pubKeysHash, hashFunc)
}

func schnorrSignMusig(msg []byte, ps []byte, k []byte,
	pubNonceX *big.Int, pubNonceY *big.Int, L []byte,
	hashFunc func([]byte) []byte) (*schnorr.Signature, error) {

	// this is global stuff in the schnorr module, copied locally here
	scalarSize := 32
	bigZero := new(big.Int).SetInt64(0)
	schnorrError := func(c schnorr.ErrorCode, desc string) error {
		return schnorr.Error{c, desc}
	}
	zeroSlice := func(s []byte) {
		for i := 0; i < scalarSize; i++ {
			s[i] = 0x00
		}
	}

	curve := secp256k1.S256()
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if len(ps) != scalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(ps), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if len(k) != scalarSize {
		str := fmt.Sprintf("wrong size for nonce k (got %v, want %v)",
			len(k), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}
	if len(L) != scalarSize {
		str := fmt.Sprintf("wrong size for hash of pubkeys L (got %v, want %v)",
			len(L), scalarSize)
		return nil, schnorrError(schnorr.ErrBadInputSize, str)
	}

	psBig := new(big.Int).SetBytes(ps)
	bigK := new(big.Int).SetBytes(k)
	bigL := new(big.Int).SetBytes(L)

	if psBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("secret scalar is zero")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if psBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("secret scalar is out of bounds")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if bigK.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("k scalar is zero")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if bigK.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("k scalar is out of bounds")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if bigL.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("L scalar is zero")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}
	if bigL.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("L scalar is out of bounds")
		return nil, schnorrError(schnorr.ErrInputValue, str)
	}

	// X = xG  (calculate pubkey from privkey)
	pubX, pubY := curve.ScalarBaseMult(ps)
	pub := secp256k1.NewPublicKey(pubX, pubY)

	// R = Sum(pubNonce[i])  (R is the sum of all pubNonces)
	var Rpx, Rpy *big.Int
	Rpx = pubNonceX
	Rpy = pubNonceY

	// Check if the field element that would be represented by Y is odd.
	// If it is, just keep k in the group order.
	if Rpy.Bit(0) == 1 {
		bigK.Mod(bigK, curve.N)
		bigK.Sub(curve.N, bigK)
	}

	// h = Hash(R || m)
	Rpxb := schnorr.BigIntToEncodedBytes(Rpx)
	hashInput := make([]byte, 0, scalarSize*2)
	hashInput = append(hashInput, Rpxb[:]...)
	hashInput = append(hashInput, msg...)
	h := hashFunc(hashInput)
	hBig := new(big.Int).SetBytes(h)

	// If the hash ends up larger than the order of the curve, abort.
	if hBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("hash of (R || m) too big")
		return nil, schnorrError(schnorr.ErrSchnorrHashValue, str)
	}

	// h2 = Hash(L || Xi)
	pubBytes := pub.Serialize()
	hashInput2 := make([]byte, 0, scalarSize+len(pubBytes))
	hashInput2 = append(hashInput2, L...)
	hashInput2 = append(hashInput2, pubBytes...)
	h2 := hashFunc(hashInput2)
	h2Big := new(big.Int).SetBytes(h2)
	if h2Big.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("hash of (L || Xi) too big")
		return nil, schnorrError(schnorr.ErrSchnorrHashValue, str)
	}

	// s = k - (h * h2 * x)
	// TODO Speed this up a bunch by using field elements, not
	// big ints. That we multiply the private scalar using big
	// ints is also probably bad because we can only assume the
	// math isn't in constant time, thus opening us up to side
	// channel attacks. Using a constant time field element
	// implementation will fix this.
	h12 := new(big.Int)
	h12.Mul(hBig, h2Big)
	sBig := new(big.Int)
	// sBig.Mul(hBig, psBig)
	sBig.Mul(h12, psBig)
	sBig.Sub(bigK, sBig)
	sBig.Mod(sBig, curve.N)

	if sBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("sig s %v is zero", sBig)
		return nil, schnorrError(schnorr.ErrZeroSigS, str)
	}

	// Zero out the private key and nonce when we're done with it.
	bigK.SetInt64(0)
	zeroSlice(k)
	psBig.SetInt64(0)
	zeroSlice(ps)

	return &schnorr.Signature{Rpx, sBig}, nil
}

// hashPubKeysMusig calculates the hash of public keys from nodes (ie, the L
// variable in the musig protocol)
func hashPubKeysMusig(pks []*secp256k1.PublicKey, hashFunc func([]byte) []byte) []byte {
	// not ideal. We could use the functions that hash in rounds, without
	// allocating all this memory.
	hashInput := make([]byte, 0, len(pks)*33)
	for _, pub := range pks {
		pubSer := pub.Serialize()
		hashInput = append(hashInput, pubSer...)
	}

	return hashFunc(hashInput)
}
