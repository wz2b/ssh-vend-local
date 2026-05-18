package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultRequestedTTLSeconds int64 = 3600

type SigningRequest struct {
	PublicKey    string `json:"public_key"`
	Principal    string `json:"principal"`
	SigningKey   string `json:"signing_key"`
	RequestedTTL string `json:"requested_ttl,omitempty"`
	Identity     string `json:"identity,omitempty"`
}

func parseSigningRequest(data []byte) (SigningRequest, int64, error) {
	var req SigningRequest

	if len(bytes.TrimSpace(data)) == 0 {
		return req, 0, errors.New("signing request is empty")
	}

	if err := json.Unmarshal(data, &req); err != nil {
		return req, 0, fmt.Errorf("parse signing request: %w", err)
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.Principal = strings.TrimSpace(req.Principal)
	req.SigningKey = strings.TrimSpace(req.SigningKey)
	req.RequestedTTL = strings.TrimSpace(req.RequestedTTL)
	req.Identity = strings.TrimSpace(req.Identity)

	if req.PublicKey == "" {
		return req, 0, errors.New("public_key is required")
	}

	if req.Principal == "" {
		return req, 0, errors.New("principal is required")
	}

	if req.SigningKey == "" {
		return req, 0, errors.New("signing_key is required")
	}

	ttlSeconds := defaultRequestedTTLSeconds
	if req.RequestedTTL != "" {
		parsedTTL, err := parseTTLSeconds(req.RequestedTTL)
		if err != nil {
			return req, 0, fmt.Errorf("requested_ttl: %w", err)
		}
		ttlSeconds = parsedTTL
	}

	if req.Identity == "" {
		req.Identity = fmt.Sprintf("ssh-vend-local-%d", time.Now().Unix())
	}

	return req, ttlSeconds, nil
}

func parseTTLSeconds(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, errors.New("ttl is required")
	}

	if duration, err := time.ParseDuration(trimmed); err == nil {
		if duration <= 0 {
			return 0, errors.New("ttl must be positive")
		}
		if duration%time.Second != 0 {
			return 0, fmt.Errorf("ttl %q must resolve to whole seconds", value)
		}
		return int64(duration / time.Second), nil
	}

	seconds, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q", value)
	}
	if seconds <= 0 {
		return 0, errors.New("ttl must be positive")
	}

	return seconds, nil
}

func validSigningKeyName(name string) bool {
	if name == "" {
		return false
	}

	if strings.Contains(name, "..") {
		return false
	}

	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}

	return true
}

func resolveSigningKeyPath(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("signing key name is required")
	}
	if !validSigningKeyName(trimmed) {
		return "", fmt.Errorf("invalid signing key name %q", name)
	}

	privatePath := filepath.Join(defaultKeysDir, trimmed)
	return privatePath, nil
}

func signCertificate(req SigningRequest, signingKeyPath string, ttlSeconds int64) (string, error) {
	caSigner, err := loadSSHSigner(signingKeyPath)
	if err != nil {
		return "", fmt.Errorf("load signing key %s: %w", signingKeyPath, err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return "", fmt.Errorf("parse public_key: %w", err)
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           req.Identity,
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(time.Duration(ttlSeconds) * time.Second).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty": "",
				// TODO: Make certificate extensions policy-driven.
			},
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return "", fmt.Errorf("sign SSH certificate: %w", err)
	}

	return string(ssh.MarshalAuthorizedKey(cert)), nil
}

func loadSSHSigner(path string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}

	return signer, nil
}
