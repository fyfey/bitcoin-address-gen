package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

// Input is a transaction input
type Input struct {
	// TxID hash where funds coming from
	TxHash string
	// Index of Output from TxID
	Index int
	// 33 Byte compressed public key
	PublicKey []byte
	// Signed TX with Public key filled in, other inputs blank
	Signature []byte
}

// Hash hashes the data - either with or without the script sig
func (i *Input) Hash() []byte {
	index := make([]byte, 4)
	bTXHash, err := hex.DecodeString(i.TxHash)
	if err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(index, uint32(i.Index))
	b1 := append(bTXHash, index...)
	b2 := append(b1, i.PublicKey...)
	//b3 := append(b2, i.Signature...)

	hash := sha256.Sum256(b2)

	return hash[:]
}

// Output is a transaction output
type Output struct {
	// Address is the hash160 hash of the address
	ToAddress []byte
	// Value being sent
	Value int
}

func (o *Output) Hash() []byte {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, uint32(o.Value))
	b1 := append(o.ToAddress, value...)
	hash := sha256.Sum256(b1)

	return hash[:]
}

// Transaction is a simple payment transaction
type Transaction struct {
	TxID    []byte
	Inputs  []*Input
	Outputs []*Output
}

func (t *Transaction) AddInput(txID string, index int, pubKey *btcec.PublicKey) {
	newInput := &Input{
		TxHash:    txID,
		Index:     index,
		PublicKey: pubKey.SerializeCompressed(),
	}
	t.Inputs = append(t.Inputs, newInput)
}

func (t *Transaction) CalcHash() []byte {
	var inputs []byte
	for _, i := range t.Inputs {
		inputs = append(inputs, i.Hash()...)
	}
	var outputs []byte
	for _, o := range t.Outputs {
		outputs = append(outputs, o.Hash()...)
	}
	b1 := append(inputs, outputs...)
	h := sha256.Sum256(b1)

	return h[:]
}

func NewTransaction() *Transaction {
	return &Transaction{
		[]byte{},
		[]*Input{},
		[]*Output{},
	}
}

// SignInput generates a signature for a given input
func (t *Transaction) HashForSig(idx int, txMap map[string]*Transaction) ([]byte, error) {
	if len(t.Inputs) < idx+1 {
		return nil, errors.New("Invalid input idx")
	}
	if _, ok := txMap[t.Inputs[idx].TxHash]; !ok {
		return nil, fmt.Errorf("Could not find txHash %s in map", t.Inputs[idx].TxHash)
	}
	hash := []byte{}
	for i := 0; i < len(t.Inputs); i++ {
		tmpPK := t.Inputs[i].PublicKey
		tmpSig := t.Inputs[i].Signature
		t.Inputs[i].PublicKey = []byte{}
		if i == idx {
			// We are signing for this one!
			t.Inputs[i].PublicKey = txMap[t.Inputs[i].TxHash].Outputs[t.Inputs[i].Index].ToAddress
		}
		t.Inputs[i].Signature = []byte{}
		t.Inputs[i].Signature = []byte{}
		hash = append(hash, t.Inputs[i].Hash()...)
		t.Inputs[i].PublicKey = tmpPK
		t.Inputs[i].Signature = tmpSig
	}
	for _, o := range t.Outputs {
		hash = append(hash, o.Hash()...)
	}

	sum := sha256.Sum256(hash)

	return sum[:], nil
}

func IssueToAddress(address string, amount int) (*Transaction, error) {
	tx := NewTransaction()
	output := &Output{
		ToAddress: AddressToHash160(address),
		Value:     amount,
	}
	tx.Outputs = append(tx.Outputs, output)
	s := sha256.Sum256(tx.CalcHash())
	tx.TxID = s[:]

	return tx, nil
}
