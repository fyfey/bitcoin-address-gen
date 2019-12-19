package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
	UTXOs       map[string]*StoredOutput
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
		UTXOs:       map[string]*StoredOutput{},
		IncomingTXs: make(chan *Transaction),
		OutgoingTxs: make(chan *Transaction),
	}
}

func (w *Wallet) Balance() (balance int) {
	// Find TX outputs
	for _, out := range w.UTXOs {
		balance += out.Output.Value
	}

	return balance
}

func UTXOHash(txHash []byte, index int) string {
	b := make([]byte, len(txHash)+4)
	copy(b, txHash)
	binary.BigEndian.PutUint32(b, uint32(index))
	sha := sha256.Sum256(b)

	return hex.EncodeToString(sha[:])
}

func (w *Wallet) Send(toAddress string, amount int) (*Transaction, error) {
	// Check balance
	fmt.Printf("[%s] Send %d coins to %s", w.Name, amount, toAddress)
	balance := w.Balance()
	if balance < amount {
		return nil, fmt.Errorf("Not enough funds. Balance is %d", balance)
	}
	tx := NewTransaction()
	totalInput := 0
	for _, out := range w.UTXOs {
		tx.AddInput(out.TxID, out.Index, w.PrivateKey.PubKey())
		totalInput += out.Output.Value
		if totalInput >= amount {
			break
		}
	}
	output := &Output{
		ToAddress: AddressToHash160(toAddress),
		Value:     amount,
	}
	tx.Outputs = append(tx.Outputs, output)
	if totalInput > amount {
		tx.Outputs = append(tx.Outputs, &Output{
			ToAddress: AddressToHash160(w.Address),
			Value:     totalInput - amount,
		})
	}

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
		for idx, output := range tx.Outputs {
			if bytes.Equal(output.ToAddress, AddressToHash160(w.Address)) {
				fmt.Printf("[%s] +%d coins! %x\n", w.Name, output.Value, tx.TxID)
				hash := UTXOHash(tx.TxID, idx)
				w.UTXOs[hash] = &StoredOutput{
					Output: output,
					TxID:   hex.EncodeToString(tx.TxID),
					Index:  idx,
				}
				w.UTXs[hex.EncodeToString(tx.TxID)] = tx
			}
		}
		for _, input := range tx.Inputs {
			if _, ok := w.UTXs[input.TxHash]; ok {
				fmt.Printf("[%s] Found spent TX %s\n", w.Name, input.TxHash)
				txIDBytes, err := hex.DecodeString(input.TxHash)
				if err != nil {
					panic(err)
				}
				if out, ok := w.UTXOs[UTXOHash(txIDBytes, input.Index)]; ok {
					fmt.Printf("[%s] Found UTXO! %s\n", w.Name, out.TxID)
					delete(w.UTXOs, UTXOHash(txIDBytes, input.Index))
					fmt.Printf("[%s] UTXO len: %d\n", w.Name, len(w.UTXOs))
				}
				spendableOutputs := 0
				for idx, out := range w.UTXs[input.TxHash].Outputs {
					if !bytes.Equal(out.ToAddress, AddressToHash160(w.Address)) {
						continue
					}
					if _, ok := w.UTXOs[UTXOHash(tx.TxID, idx)]; ok {
						spendableOutputs++
						break
					}
				}
				if spendableOutputs == 0 {
					fmt.Printf("[%s] No more outputs on this tx. Deleting %x\n", w.Name, tx.TxID)
					delete(w.UTXs, input.TxHash)
				}
			}
		}
	}
}
