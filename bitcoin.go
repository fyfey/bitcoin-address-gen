package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// Hash160 creates the ripe(sha256(pubKeyHash)) hash
func Hash160(pubKeyHash []byte) []byte {
	shaHash := sha256.Sum256(pubKeyHash)
	ripe := ripemd160.New()
	ripe.Write(shaHash[:])

	return ripe.Sum(nil)
}

// PubKeyHash generates a 33 byte pubKey from a ecdsa key pair
func PubKeyHash(privateKey *ecdsa.PrivateKey) []byte {
	var prefix byte = 0x01
	if privateKey.Y.Bit(0) == 0 {
		prefix = 0x02
	}
	return append([]byte{prefix}, privateKey.PublicKey.X.Bytes()...)
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
func Verify(signature []byte, publicKey *ecdsa.PublicKey, payload []byte) bool {
	r := big.NewInt(0)
	r = r.SetBytes(signature[:32])
	s := big.NewInt(0)
	s = s.SetBytes(signature[32:])

	return ecdsa.Verify(publicKey, payload, r, s)
}
