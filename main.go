package main

import (
	"fmt"
	"time"
)

// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
func main() {

	hub := NewHub()

	bobWallet := hub.NewWallet("Bob")
	aliceWallet := hub.NewWallet("Alice")

	go hub.Run()
	go bobWallet.Listen()
	go aliceWallet.Listen()

	coinbase, err := IssueToAddress(bobWallet.Address, 100)
	if err != nil {
		panic(err)
	}
	hub.Submission <- coinbase

	time.Sleep(time.Millisecond * 500)

	_, err = bobWallet.Send(aliceWallet.Address, 10)
	if err != nil {
		panic(err)
	}

	ch := make(chan bool)

	fmt.Println("wait")

	go func() {
		for {
			time.Sleep(time.Millisecond * 500)
			fmt.Printf("[Wallet] Bob balance:   %d\n", bobWallet.Balance())
			fmt.Printf("[Wallet] Alice balance: %d\n", aliceWallet.Balance())
		}
	}()
	<-ch

	// Bob sending 10 to alice
	// bob := NewKey()
	// alice := NewKey()

	// txStore := map[string]*Transaction{}

	// bobAddr := Hash160(bob.PubKey().SerializeCompressed())
	// aliceAddr := Hash160(alice.PubKey().SerializeCompressed())

	// fmt.Printf("Coinbase sending 10 to %s\n", Hash160ToAddress(bobAddr))

	// // "Coinbase" TX
	// txA, _ := IssueToAddress(PubKeyToAddress(bob.PubKey()), 10)
	// txStore[hex.EncodeToString(txA.TxID)] = txA

	// fmt.Printf("txAHash: %x\n", txA.CalcHash())
	// fmt.Printf("TxA ID:  %x\n", txA.TxID)

	// Bob sending to alice

	// txB, err := Send(PubKeyToAddress(bob.PubKey()), PubKeyToAddress(alice.PubKey()), 10)

	// txB := NewTransaction()
	// txB.AddInput(fmt.Sprintf("%x", txA.TxID), 0, bob.PubKey())
	// aliceOutput := &Output{
	// 	ToAddress: aliceAddr,
	// 	Value:     10,
	// }
	// txB.Outputs = append(txB.Outputs, aliceOutput)
	// txBHash := txB.CalcHash()

	// fmt.Printf("txBHash: %x\n", txBHash)
	// fmt.Printf("txBHash: %x\n", txB.CalcHash())

	// sigHash, err := txB.HashForSig(0, txStore)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("SigHash A: %x\n", sigHash)
	// sig, err := bob.Sign(sigHash)
	// if err != nil {
	// 	panic(err)
	// }

	// txB.Inputs[0].Signature = sig.Serialize()

	// fmt.Printf("Input 0: PubKey: %x\n", txB.Inputs[0].PublicKey)
	// fmt.Printf("Input 0: Sig: %x\n", txB.Inputs[0].Signature)

	// fmt.Printf("\nAttempt to verify...\n")

	// // Lets mess with the TX!
	// txB.Outputs[0].Value = 10

	// sigHashAgain, err := txB.HashForSig(0, txStore)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("SigHash B: %x\n", sigHashAgain)
	// ok := Verify(txB.Inputs[0].Signature, txB.Inputs[0].PublicKey, sigHashAgain)
	// //ok := reformedSig.Verify(sigHashAgain, alicePubReformed)
	// if ok {
	// 	fmt.Println("OK!")
	// } else {
	// 	fmt.Println("Verify failed")
	// }
}
