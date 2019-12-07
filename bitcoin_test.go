package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

const (
	TestPubKeyHash = "02c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34e"
)

func TestHash160(t *testing.T) {
	testBytes, _ := hex.DecodeString(TestPubKeyHash)
	expected := "5fb0e9755a3424efd2ba0587d20b1e98ee29814a"

	hash160 := Hash160(testBytes)
	hex := hex.EncodeToString(hash160)

	if hex != expected {
		t.Errorf("Hash160 failed. Expected %s; got %x", expected, hex)
	}
}

func TestHash160ToAddress(t *testing.T) {
	testBytes, _ := hex.DecodeString(TestPubKeyHash)
	expected := "19iy8HKpG5EbsqB2GUNVPUDbQxiTrPXpsx"

	result := Hash160ToAddress(Hash160(testBytes))

	if result != expected {
		t.Errorf("PubKeyHashToAddress failed. Expected %s; got %s", expected, result)
	}
}

func TestAddressToHash160(t *testing.T) {
	address := "19iy8HKpG5EbsqB2GUNVPUDbQxiTrPXpsx"
	expected := "5fb0e9755a3424efd2ba0587d20b1e98ee29814a"

	result := AddressToHash160(address)
	hex := hex.EncodeToString(result)

	if hex != expected {
		t.Errorf("AddressToHash160 fail. Expected %s; got %s", expected, hex)
	}
}

func TestSignAndVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	payload := []byte("hi there!")

	sig, err := Sign(privateKey, payload)
	if err != nil {
		panic(err)
	}

	ok := Verify(sig, &privateKey.PublicKey, payload)

	if ok == false {
		t.Errorf("Verification failed\n")
	}
}
