package main

import (
	"encoding/hex"
	"fmt"
)

// Hub is a broadcast hub for wallets
type Hub struct {
	Wallets    []*Wallet
	Submission chan *Transaction
	txStore    map[string]*Transaction
}

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		[]*Wallet{},
		make(chan *Transaction),
		map[string]*Transaction{},
	}
}

func (h *Hub) Run() {
	for tx := range h.Submission {
		fmt.Printf("[Hub] Got submission of %x\n", tx.TxID)

		// Verify TX
	Outer:
		for idx, input := range tx.Inputs {
			hash, err := tx.HashForSig(idx, h.txStore)
			if err != nil {
				panic(err)
			}
			if ok := Verify(input.Signature, input.PublicKey, hash); !ok {
				fmt.Printf("[Hub] Verify fail for %x on input %d\n", tx.TxID, idx)
				continue Outer
			}
		}
		if len(tx.Inputs) == 0 {
			fmt.Printf("[Hub] *** Issuance of %d to %s ***\n", tx.Outputs[0].Value, Hash160ToAddress(tx.Outputs[0].ToAddress))
		}
		inputValue := 0
		outputValue := 0

		for _, input := range tx.Inputs {
			sendingOutput := h.txStore[input.TxHash].Outputs[input.Index]
			inputValue += sendingOutput.Value
		}
		for _, output := range tx.Outputs {
			outputValue += output.Value
		}

		txFee := inputValue - outputValue
		fmt.Printf("In: %d, out: %d, fee: %d\n", inputValue, outputValue, txFee)

		if len(tx.Inputs) > 0 && outputValue > inputValue {
			panic("Output greater than input!")
		}

		txID := hex.EncodeToString(tx.TxID)
		fmt.Printf("[Hub] TX OK! %x\n", tx.TxID)
		h.txStore[txID] = tx

		for _, w := range h.Wallets {
			fmt.Printf("[Hub] Sending to %s\n", w.Name)
			w.IncomingTXs <- tx
		}
	}
}

// NewWallet creates a new wallet and hooks it up to the "network"
func (h *Hub) NewWallet(name string) *Wallet {
	wallet := NewWallet(name)
	h.Wallets = append(h.Wallets, wallet)
	go func() {
		for tx := range wallet.OutgoingTxs {
			h.Submission <- tx
		}
	}()
	return wallet
}
