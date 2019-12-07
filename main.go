package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

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

	sig, err := Sign(privateKey, payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Sig: %x\n", sig)

	ok := Verify(sig, &privateKey.PublicKey, payload)
	fmt.Printf("OK? %v\n", ok)

	pubKeyHash := PubKeyHash(privateKey)
	fmt.Printf("pubKeyHash: %x\n", pubKeyHash)

	address := Hash160ToAddress(Hash160(pubKeyHash))
	fmt.Printf("Address: %s (%x)\n", address, address)

	two := sha256.Sum256(pubKeyHash)
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
