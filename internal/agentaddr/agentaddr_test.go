package agentaddr

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestAgentAddr120ExactLength(t *testing.T) {
	_, privateKey := testKeyPair(t)
	payload := testPayload(t)

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
	if SignatureSize != 64 {
		t.Fatalf("signature size = %d, want exactly 64", SignatureSize)
	}
}

func TestAgentAddr120ExactPayloadLength(t *testing.T) {
	_, privateKey := testKeyPair(t)
	payload := testPayload(t)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	payloadBytes := encoded[:PayloadSize]
	if len(payloadBytes) != PayloadSize {
		t.Fatalf("payload length = %d, want %d", len(payloadBytes), PayloadSize)
	}
	if len(payloadBytes) != 56 {
		t.Fatalf("payload length = %d, want exactly 56", len(payloadBytes))
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
	payload := testPayload(t)

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
	payload := testPayload(t)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	encoded[factsPtrHashOffset] ^= 0xff

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(publicKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verify tampered record error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	_, privateKey := testKeyPair(t)
	payload := testPayload(t)

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
	_, privateKey := testKeyPair(t)
	payload := testPayload(t)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encoded := record.Encode()
	encoded[ttlOffset] = 0
	encoded[ttlOffset+1] = 0

	_, err = Decode(encoded)
	if !errors.Is(err, ErrZeroTTL) {
		t.Fatalf("decode zero ttl error = %v, want %v", err, ErrZeroTTL)
	}
}

func TestPayloadFieldRoundTrip(t *testing.T) {
	_, privateKey := testKeyPair(t)
	payload := testPayload(t)

	record, err := Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded, err := Decode(record.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	got := decoded.Payload()
	if got.Sequence != payload.Sequence {
		t.Fatalf("sequence = %d, want %d", got.Sequence, payload.Sequence)
	}
	if got.FactsPtrHash128 != payload.FactsPtrHash128 {
		t.Fatalf("facts ptr hash = %x, want %x", got.FactsPtrHash128, payload.FactsPtrHash128)
	}
	if got.CredentialSet128 != payload.CredentialSet128 {
		t.Fatalf("credential set hash = %x, want %x", got.CredentialSet128, payload.CredentialSet128)
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

	hashA, err := AgentIDHash("  Alice.Example ")
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hashB, err := AgentIDHash("alice.example")
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("normalized hashes differ: %x != %x", hashA, hashB)
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

func testPayload(t *testing.T) Payload {
	t.Helper()

	payload, err := New(
		"agent.example",
		300,
		0x01,
		42,
		Hash128([]byte("facts pointer")),
		Hash128([]byte("credential set")),
	)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}

	return payload
}
