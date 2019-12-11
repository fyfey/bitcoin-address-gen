package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
func main() {
	// Bob sending 10 to alice
	bob := NewKey()
	alice := NewKey()

	txStore := map[string]*Transaction{}

	bobAddr := Hash160(bob.PubKey().SerializeCompressed())
	aliceAddr := Hash160(alice.PubKey().SerializeCompressed())

	fmt.Printf("Coinbase sending 10 to %s\n", Hash160ToAddress(bobAddr))

	// "Coinbase" TX
	txA := NewTransaction()
	output := &Output{
		ToAddress: bobAddr,
		Value:     10,
	}
	txA.Outputs = append(txA.Outputs, output)
	txAID := sha256.Sum256(txA.CalcHash())

	txStore[hex.EncodeToString(txAID[:])] = txA

	fmt.Printf("txAHash: %x\n", txA.CalcHash())
	fmt.Printf("TxA ID:  %x\n", txAID)

	// Bob sending to alice
	txB := NewTransaction()
	txB.AddInput(fmt.Sprintf("%x", txAID), 0, alice.PubKey())
	aliceOutput := &Output{
		ToAddress: aliceAddr,
		Value:     10,
	}
	txB.Outputs = append(txB.Outputs, aliceOutput)
	txBHash := txB.CalcHash()

	fmt.Printf("txBHash: %x\n", txBHash)
	fmt.Printf("txBHash: %x\n", txB.CalcHash())

	sigHash, err := txB.HashForSig(0, txStore)
	if err != nil {
		panic(err)
	}
	fmt.Printf("SigHash A: %x\n", sigHash)
	sig, err := alice.Sign(sigHash)
	if err != nil {
		panic(err)
	}

	txB.Inputs[0].Signature = sig.Serialize()

	fmt.Printf("Input 0: PubKey: %x\n", txB.Inputs[0].PublicKey)
	fmt.Printf("Input 0: Sig: %x\n", txB.Inputs[0].Signature)

	fmt.Printf("\nAttempt to verify...\n")

	// Lets mess with the TX!
	txB.Outputs[0].Value = 10

	sigHashAgain, err := txB.HashForSig(0, txStore)
	if err != nil {
		panic(err)
	}

	fmt.Printf("SigHash B: %x\n", sigHashAgain)
	ok := Verify(txB.Inputs[0].Signature, txB.Inputs[0].PublicKey, sigHashAgain)
	//ok := reformedSig.Verify(sigHashAgain, alicePubReformed)
	if ok {
		fmt.Println("OK!")
	} else {
		fmt.Println("Verify failed")
	}
}
