package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/ockam-network/did"
)

const errInvalidKeyDIDFmt = "invalid key DID: %w"
const errUnsupportedKeyTypeFmt = "unsupported key type: %s"

type DocumentResolver interface {
	Resolve(did *did.DID) error
}

type KeyDID struct {
	PublicKey ecdsa.PublicKey
}

func ParseKeyDID(input string) (*KeyDID, error) {
	result, err := did.Parse(input)
	if err != nil {
		return nil, err
	}
	if result.Method != "key" {
		return nil, fmt.Errorf("unsupported DID method: %s", result.Method)
	}

	encoding, decodedBytes, err := multibase.Decode(result.ID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyDIDFmt, err)
	}
	if encoding != multibase.Base58BTC {
		return nil, fmt.Errorf(errInvalidKeyDIDFmt, errors.New("not btc58 encoded"))
	}
	var curve elliptic.Curve
	// TODO: Support other curves than just NIST stuff
	keyType, err := binary.ReadUvarint(bytes.NewReader(decodedBytes))
	if err != nil {
		return nil, fmt.Errorf(errInvalidKeyDIDFmt, err)
	}
	keyBytes := decodedBytes[8:]
	switch multicodec.Code(keyType) {
	case multicodec.Ed25519Pub:
		publicKey := ed25519.PublicKey(keyBytes)

		return nil, fmt.Errorf(errUnsupportedKeyTypeFmt, "Ed25519")
	case multicodec.X25519Pub:

		return nil, fmt.Errorf(errUnsupportedKeyTypeFmt, "X25519")
	case multicodec.Secp256k1Pub:
		return nil, fmt.Errorf(errUnsupportedKeyTypeFmt, "Secp256k1")
	case multicodec.P256Pub:
		curve = elliptic.P256()
		break
	case multicodec.P384Pub:
		curve = elliptic.P384()
		break
	case multicodec.P521Pub:
		curve = elliptic.P521()
		break
	default:
		return nil, fmt.Errorf(errUnsupportedKeyTypeFmt, fmt.Sprintf("%d", keyType))
	}

	if x, y := elliptic.Unmarshal(curve, keyBytes); x == nil {
		return nil, fmt.Errorf(errInvalidKeyDIDFmt, errors.New("unable to unmarshal EC"))
	} else {
		return &KeyDID{PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}}, nil
	}
}
