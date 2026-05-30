package agentaddr

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	Version1      byte = 1
	PayloadSize        = 56
	SignatureSize      = ed25519.SignatureSize
	RecordSize         = PayloadSize + SignatureSize

	versionOffset       = 0
	ttlOffset           = 1
	agentIDHashOffset   = 5
	publicKeyHashOffset = 21
	nonceOffset         = 37
	nonceSize           = PayloadSize - nonceOffset
)

var (
	ErrInvalidRecordLength = errors.New("agent address record must be exactly 120 bytes")
	ErrUnsupportedVersion  = errors.New("unsupported agent address version")
	ErrZeroTTL             = errors.New("agent address ttl must be greater than zero")
	ErrInvalidPublicKey    = errors.New("invalid ed25519 public key")
	ErrInvalidPrivateKey   = errors.New("invalid ed25519 private key")
	ErrInvalidSignature    = errors.New("invalid agent address signature")
)

type AgentAddr120 struct {
	payload   [PayloadSize]byte
	signature [SignatureSize]byte
}

type Payload struct {
	Version       byte
	TTLSeconds    uint32
	AgentIDHash   [16]byte
	PublicKeyHash [16]byte
	Nonce         [nonceSize]byte
}

func New(agentID string, ttlSeconds uint32, publicKey ed25519.PublicKey) (Payload, error) {
	if ttlSeconds == 0 {
		return Payload{}, ErrZeroTTL
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Payload{}, ErrInvalidPublicKey
	}

	agentIDHash, err := AgentIDHash(agentID)
	if err != nil {
		return Payload{}, err
	}

	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return Payload{}, err
	}

	return Payload{
		Version:       Version1,
		TTLSeconds:    ttlSeconds,
		AgentIDHash:   agentIDHash,
		PublicKeyHash: Hash128(publicKey),
		Nonce:         nonce,
	}, nil
}

func Sign(payload Payload, privateKey ed25519.PrivateKey) (AgentAddr120, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return AgentAddr120{}, ErrInvalidPrivateKey
	}

	payloadBytes, err := encodePayload(payload)
	if err != nil {
		return AgentAddr120{}, err
	}

	signature := ed25519.Sign(privateKey, payloadBytes[:])

	var record AgentAddr120
	record.payload = payloadBytes
	copy(record.signature[:], signature)
	return record, nil
}

func Decode(record []byte) (AgentAddr120, error) {
	if len(record) != RecordSize {
		return AgentAddr120{}, ErrInvalidRecordLength
	}

	var addr AgentAddr120
	copy(addr.payload[:], record[:PayloadSize])
	copy(addr.signature[:], record[PayloadSize:])

	if err := validatePayloadBytes(addr.payload); err != nil {
		return AgentAddr120{}, err
	}

	return addr, nil
}

func (a AgentAddr120) Encode() []byte {
	out := make([]byte, RecordSize)
	copy(out[:PayloadSize], a.payload[:])
	copy(out[PayloadSize:], a.signature[:])
	return out
}

func (a AgentAddr120) Payload() Payload {
	return decodePayload(a.payload)
}

func (a AgentAddr120) Verify(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	if Hash128(publicKey) != a.Payload().PublicKeyHash {
		return ErrInvalidPublicKey
	}
	if !ed25519.Verify(publicKey, a.payload[:], a.signature[:]) {
		return ErrInvalidSignature
	}

	return nil
}

func encodePayload(payload Payload) ([PayloadSize]byte, error) {
	var out [PayloadSize]byte
	out[versionOffset] = payload.Version
	binary.BigEndian.PutUint32(out[ttlOffset:agentIDHashOffset], payload.TTLSeconds)
	copy(out[agentIDHashOffset:publicKeyHashOffset], payload.AgentIDHash[:])
	copy(out[publicKeyHashOffset:nonceOffset], payload.PublicKeyHash[:])
	copy(out[nonceOffset:], payload.Nonce[:])

	if err := validatePayloadBytes(out); err != nil {
		return [PayloadSize]byte{}, err
	}

	return out, nil
}

func decodePayload(payload [PayloadSize]byte) Payload {
	var out Payload
	out.Version = payload[versionOffset]
	out.TTLSeconds = binary.BigEndian.Uint32(payload[ttlOffset:agentIDHashOffset])
	copy(out.AgentIDHash[:], payload[agentIDHashOffset:publicKeyHashOffset])
	copy(out.PublicKeyHash[:], payload[publicKeyHashOffset:nonceOffset])
	copy(out.Nonce[:], payload[nonceOffset:])
	return out
}

func validatePayloadBytes(payload [PayloadSize]byte) error {
	if payload[versionOffset] != Version1 {
		return ErrUnsupportedVersion
	}
	if binary.BigEndian.Uint32(payload[ttlOffset:agentIDHashOffset]) == 0 {
		return ErrZeroTTL
	}

	return nil
}
