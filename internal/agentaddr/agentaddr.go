package agentaddr

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const (
	Version1      byte = 1
	PayloadSize        = 56
	SignatureSize      = ed25519.SignatureSize
	RecordSize         = PayloadSize + SignatureSize

	versionOffset          = 0
	flagsOffset            = 1
	ttlOffset              = 2
	sequenceOffset         = 4
	agentIDHashOffset      = 8
	factsPtrHashOffset     = 24
	credentialSet128Offset = 40
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
	Version          byte
	Flags            byte
	TTLSeconds       uint16
	Sequence         uint32
	AgentIDHash      [16]byte
	FactsPtrHash128  [16]byte
	CredentialSet128 [16]byte
}

func New(agentID string, ttlSeconds uint16, flags byte, sequence uint32, factsPtrHash128 [16]byte, credentialSet128 [16]byte) (Payload, error) {
	if ttlSeconds == 0 {
		return Payload{}, ErrZeroTTL
	}

	agentIDHash, err := AgentIDHash(agentID)
	if err != nil {
		return Payload{}, err
	}

	return Payload{
		Version:          Version1,
		Flags:            flags,
		TTLSeconds:       ttlSeconds,
		Sequence:         sequence,
		AgentIDHash:      agentIDHash,
		FactsPtrHash128:  factsPtrHash128,
		CredentialSet128: credentialSet128,
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
	if !ed25519.Verify(publicKey, a.payload[:], a.signature[:]) {
		return ErrInvalidSignature
	}

	return nil
}

func encodePayload(payload Payload) ([PayloadSize]byte, error) {
	var out [PayloadSize]byte
	out[versionOffset] = payload.Version
	out[flagsOffset] = payload.Flags
	binary.BigEndian.PutUint16(out[ttlOffset:sequenceOffset], payload.TTLSeconds)
	binary.BigEndian.PutUint32(out[sequenceOffset:agentIDHashOffset], payload.Sequence)
	copy(out[agentIDHashOffset:factsPtrHashOffset], payload.AgentIDHash[:])
	copy(out[factsPtrHashOffset:credentialSet128Offset], payload.FactsPtrHash128[:])
	copy(out[credentialSet128Offset:], payload.CredentialSet128[:])

	if err := validatePayloadBytes(out); err != nil {
		return [PayloadSize]byte{}, err
	}

	return out, nil
}

func decodePayload(payload [PayloadSize]byte) Payload {
	var out Payload
	out.Version = payload[versionOffset]
	out.Flags = payload[flagsOffset]
	out.TTLSeconds = binary.BigEndian.Uint16(payload[ttlOffset:sequenceOffset])
	out.Sequence = binary.BigEndian.Uint32(payload[sequenceOffset:agentIDHashOffset])
	copy(out.AgentIDHash[:], payload[agentIDHashOffset:factsPtrHashOffset])
	copy(out.FactsPtrHash128[:], payload[factsPtrHashOffset:credentialSet128Offset])
	copy(out.CredentialSet128[:], payload[credentialSet128Offset:])
	return out
}

func validatePayloadBytes(payload [PayloadSize]byte) error {
	if payload[versionOffset] != Version1 {
		return ErrUnsupportedVersion
	}
	if binary.BigEndian.Uint16(payload[ttlOffset:sequenceOffset]) == 0 {
		return ErrZeroTTL
	}

	return nil
}
