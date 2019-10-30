package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcutil/base58"

	"golang.org/x/crypto/ripemd160"
)

// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
func main() {
	// Create private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	payload := []byte("hi there!")
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, payload)

	// Concat r + s for creating a single 64 byte signature
	sig := append(r.Bytes(), s.Bytes()...)

	// Convert to hex for display
	sigString := hex.EncodeToString(sig)
	fmt.Printf("Sig: %s\n", sigString)

	// Start verification - Read in bytes
	sigBytes, _ := hex.DecodeString(sigString)

	// recreate r + s from splitting the []byte in half
	r = big.NewInt(0)
	r = r.SetBytes(sigBytes[:32])
	s = big.NewInt(0)
	s = s.SetBytes(sigBytes[32:])

	// verify payload
	ok := ecdsa.Verify(&privateKey.PublicKey, payload, r, s)
	fmt.Printf("OK? %v\n\n", ok)

	fmt.Printf("Priv:  %x\n", privateKey.D.Bytes())

	fmt.Printf("Pub.X: %x\n", privateKey.PublicKey.X)
	var prefix byte
	if privateKey.Y.Bit(0) == 0 {
		prefix = 0x02
	} else {
		prefix = 0x01
	}
	one := append([]byte{prefix}, privateKey.PublicKey.X.Bytes()...)
	fmt.Printf("One:   %x\n", one)

	two := sha256.Sum256(one)
	fmt.Printf("Two:   %x\n", two)

	ripe := ripemd160.New()
	ripe.Write(two[:])

	three := ripe.Sum(nil)
	fmt.Printf("Three: %x\n", three)

	four := append([]byte{0x00}, three...)
	fmt.Printf("Four:  %x\n", four)

	five := sha256.Sum256(four)
	fmt.Printf("Five:  %x\n", five)

	six := sha256.Sum256(five[:])
	fmt.Printf("Six:   %x\n", six)

	checksum := six[0:4]
	fmt.Printf("chksm: %x\n", checksum)

	eight := append(four, checksum...)
	fmt.Printf("eight: %x\n", eight)

	nine := base58.Encode(eight)
	fmt.Printf("nine:  %s\n", nine)
}
