package main

import (
	"fmt"
	"testing"
)

func TestHash(t *testing.T) {

	// Bob sending 10 to alice
	bob := NewKey()
	alice := NewKey()

	aliceAddr := Hash160(alice.PubKey().SerializeCompressed())

	fmt.Printf("Bob: %s", Hash160ToAddress(Hash160(bob.PubKey().SerializeCompressed())))
	fmt.Printf("Alice: %s", Hash160ToAddress(Hash160(alice.PubKey().SerializeCompressed())))

	txA := NewTransaction()
	output := &Output{
		ToAddress: aliceAddr,
		Value:     10,
	}
	txA.Outputs = append(txA.Outputs, output)

	fmt.Printf("txAID: %x", txA.CalcHash())
}
