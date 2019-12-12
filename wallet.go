package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

type Wallet struct {
	PrivateKey *btcec.PrivateKey
	UTXs       map[string]*Transaction
}

func (w *Wallet) getUTXOs() map[string]*Output {
	UTXOs := map[string]*Output{}
	for _, tx := range w.UTXs {
		for _, out := range tx.Outputs {
			if out.ToAddress == ourAddress {
				UTXOs[tx.TxID] = out
			}
		}
	}

	return UTXOs
}

func (w *Wallet) Balance() (balance int) {
	ourAddress := Hash160(w.PrivateKey.PubKey().SerializeCompressed)
	// Find TX outputs
	for _, out := range w.getUTXOs() {
		balance += out.Value
	}

	return balance
}

func (w *Wallet) Send(toAddress string, amount int) (*Transaction, error) {
	// Check balance
	balance := w.Balance()
	if balance < amount {
		return nil, fmt.Errorf("Not enough funds. Balance is %d", balance)
	}
	tx := NewTransaction()
	for _, out := range w.getUTXOs() {
		tx.AddInput(fmt.Sprintf("%x", tx.TxID), 0, w.PrivateKey.PubKey())
	}
	aliceOutput := &Output{
		ToAddress: AddressToHash160(toAddress),
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
	sig, err := bob.Sign(sigHash)
	if err != nil {
		panic(err)
	}

	txB.Inputs[0].Signature = sig.Serialize()
}
