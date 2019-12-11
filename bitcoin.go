package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func NewKey() *btcec.PrivateKey {
	key, _ := btcec.NewPrivateKey(btcec.S256())
	return key
}

// DecompressPublicKey creates a ecdsa.PublicKey from PubKeyHash
func DecompressPublicKey(compressed []byte) (*btcec.PublicKey, error) {
	pubKey, err := btcec.ParsePubKey(compressed, btcec.S256())
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// Hash160 creates the ripe(sha256(pubKeyHash)) hash
func Hash160(pubKeyHash []byte) []byte {
	shaHash := sha256.Sum256(pubKeyHash)
	ripe := ripemd160.New()
	ripe.Write(shaHash[:])

	return ripe.Sum(nil)
}

func doubleSha(data []byte) []byte {
	one := sha256.Sum256(data)
	two := sha256.Sum256(one[:])

	return two[:]
}

func checksum(versioned []byte) []byte {
	hashed := doubleSha(versioned)

	return hashed[0:4]
}

// Hash160ToAddress converts a pubKeyHash into an address
func Hash160ToAddress(hash160 []byte) string {
	versioned := append([]byte{0x00}, hash160...)
	eight := append(versioned, checksum(versioned)...)

	return base58.Encode(eight)
}

// AddressToHash160 converts a string address back to hash160
func AddressToHash160(address string) []byte {
	decoded := base58.Decode(address)

	return decoded[1:21]
}

// Sign signs a payload with privateKey. The result is a 64 byte slice
func Sign(privateKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, payload)
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

// Verify verifies a signature
func Verify(signature []byte, pubKeyHash []byte, payload []byte) bool {
	publicKey, err := btcec.ParsePubKey(pubKeyHash, btcec.S256())
	if err != nil {
		panic(err)
	}

	sig, err := btcec.ParseSignature(signature, btcec.S256())
	if err != nil {
		panic(err)
	}

	return sig.Verify(payload, publicKey)
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex in source file: " + s)
	}
	return r
}
