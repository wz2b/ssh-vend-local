package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type EphemeralKeyPair struct {
	PrivPEM []byte
	PubAuth string
	Type    string
}

func GenEphemeralKeypair(keyType string) (*EphemeralKeyPair, error) {
	switch keyType {
	case "ed25519", "":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return marshalEphemeralKey(priv, "ed25519")
	case "rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, fmt.Errorf("generate rsa key: %w", err)
		}
		return marshalEphemeralKey(priv, "rsa")
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func marshalEphemeralKey(privateKey any, keyType string) (*EphemeralKeyPair, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create SSH signer: %w", err)
	}

	pubAuth := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	block, err := ssh.MarshalPrivateKey(privateKey, "ssh-vend-local ephemeral key")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("encode private key PEM: %w", err)
	}

	return &EphemeralKeyPair{PrivPEM: buf.Bytes(), PubAuth: pubAuth, Type: keyType}, nil
}
