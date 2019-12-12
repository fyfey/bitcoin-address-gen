package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

type StoredOutput struct {
	TxID   string
	Output *Output
	Index  int
}

type Wallet struct {
	Name        string
	Address     string
	PrivateKey  *btcec.PrivateKey
	UTXs        map[string]*Transaction
	IncomingTXs chan *Transaction
	OutgoingTxs chan *Transaction
}

func NewWallet(name string) *Wallet {
	key := NewKey()
	return &Wallet{
		Name:        name,
		PrivateKey:  key,
		Address:     PubKeyToAddress(key.PubKey()),
		UTXs:        map[string]*Transaction{},
		IncomingTXs: make(chan *Transaction),
		OutgoingTxs: make(chan *Transaction),
	}
}

func (w *Wallet) getUTXOs() map[string]*StoredOutput {
	UTXOs := map[string]*StoredOutput{}
	for _, tx := range w.UTXs {
		for idx, out := range tx.Outputs {
			if bytes.Equal(out.ToAddress, AddressToHash160(w.Address)) {
				txIDStr := hex.EncodeToString(tx.TxID)
				UTXOs[txIDStr] = &StoredOutput{
					Output: out,
					Index:  idx,
				}
			}
		}
	}

	return UTXOs
}

func (w *Wallet) Balance() (balance int) {
	// Find TX outputs
	for _, out := range w.getUTXOs() {
		balance += out.Output.Value
	}

	return balance
}

func (w *Wallet) Send(toAddress string, amount int) (*Transaction, error) {
	// Check balance
	fmt.Printf("[%s] Send %d coins to %s", w.Name, amount, toAddress)
	balance := w.Balance()
	if balance < amount {
		return nil, fmt.Errorf("Not enough funds. Balance is %d", balance)
	}
	tx := NewTransaction()
	for txID, out := range w.getUTXOs() {
		tx.AddInput(txID, out.Index, w.PrivateKey.PubKey())
	}
	output := &Output{
		ToAddress: AddressToHash160(toAddress),
		Value:     10,
	}
	tx.Outputs = append(tx.Outputs, output)

	sigHash, err := tx.HashForSig(0, w.UTXs)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("SigHash A: %x\n", sigHash)
	sig, err := w.PrivateKey.Sign(sigHash)
	if err != nil {
		panic(err)
	}

	tx.Inputs[0].Signature = sig.Serialize()
	tx.TxID = tx.CalcHash()

	w.OutgoingTxs <- tx

	return tx, nil
}

func (w *Wallet) Listen() {
	for tx := range w.IncomingTXs {
		fmt.Printf("[%s] Got TX %x\n", w.Name, tx.TxID)
		for _, output := range tx.Outputs {
			if bytes.Equal(output.ToAddress, AddressToHash160(w.Address)) {
				fmt.Printf("[%s] +%d coins! %x\n", w.Name, output.Value, tx.TxID)
				w.UTXs[fmt.Sprintf("%x", tx.TxID)] = tx
			}
		}
	}
}
