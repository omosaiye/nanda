package agentaddr

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestAgentAddr120ExactLength(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	payload := testPayload(t, publicKey)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	if len(encoded) != RecordSize {
		t.Fatalf("record length = %d, want %d", len(encoded), RecordSize)
	}
	if len(encoded) != 120 {
		t.Fatalf("record length = %d, want exactly 120", len(encoded))
	}
}

func TestDecodeRejectsShortRecord(t *testing.T) {
	_, err := Decode(make([]byte, RecordSize-1))
	if !errors.Is(err, ErrInvalidRecordLength) {
		t.Fatalf("Decode short record error = %v, want %v", err, ErrInvalidRecordLength)
	}
}

func TestDecodeRejectsLongRecord(t *testing.T) {
	_, err := Decode(make([]byte, RecordSize+1))
	if !errors.Is(err, ErrInvalidRecordLength) {
		t.Fatalf("Decode long record error = %v, want %v", err, ErrInvalidRecordLength)
	}
}

func TestVerifyValidSignature(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	payload := testPayload(t, publicKey)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded, err := Decode(record.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(publicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyTamperedRecordFails(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	payload := testPayload(t, publicKey)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	encoded[nonceOffset] ^= 0xff

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(publicKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify tampered record error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	payload := testPayload(t, publicKey)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	encoded[versionOffset] = 2

	_, err = Decode(encoded)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("decode unsupported version error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestDecodeRejectsZeroTTL(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	payload := testPayload(t, publicKey)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	encoded[ttlOffset] = 0
	encoded[ttlOffset+1] = 0
	encoded[ttlOffset+2] = 0
	encoded[ttlOffset+3] = 0

	_, err = Decode(encoded)
	if !errors.Is(err, ErrZeroTTL) {
		t.Fatalf("decode zero ttl error = %v, want %v", err, ErrZeroTTL)
	}
}

func TestNormalizeAgentIDDeterministic(t *testing.T) {
	a, err := NormalizeAgentID("  Alice.Example ")
	if err != nil {
		t.Fatalf("normalize a: %v", err)
	}
	b, err := NormalizeAgentID("alice.example")
	if err != nil {
		t.Fatalf("normalize b: %v", err)
	}

	if a != b {
		t.Fatalf("normalized ids differ: %q != %q", a, b)
	}
}

func TestHash128Deterministic(t *testing.T) {
	a := Hash128([]byte("agent.example"))
	b := Hash128([]byte("agent.example"))
	c := Hash128([]byte("other.example"))

	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("same input produced different Hash128 values")
	}
	if bytes.Equal(a[:], c[:]) {
		t.Fatal("different inputs produced same Hash128 values")
	}
}

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return publicKey, privateKey
}

func testPayload(t *testing.T, publicKey ed25519.PublicKey) Payload {
	t.Helper()

	payload, err := New("agent.example", 300, publicKey)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}

	return payload
}
