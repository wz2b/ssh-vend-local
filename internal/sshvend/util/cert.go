package util

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func ParseCertificateLine(certLine string) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		return nil, fmt.Errorf("parse authorized key line: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("signed key is not an SSH certificate")
	}

	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("expected user certificate, got cert type %d", cert.CertType)
	}

	return cert, nil
}

func LifetimeSeconds(ttl string) (uint32, error) {
	if ttl == "" {
		return 0, nil
	}

	duration, err := time.ParseDuration(ttl)
	if err != nil {
		return 0, fmt.Errorf("parse ttl %q: %w", ttl, err)
	}

	if duration <= 0 {
		return 0, errors.New("ttl must be positive")
	}

	if duration%time.Second != 0 {
		return 0, fmt.Errorf("ttl %q must resolve to whole seconds", ttl)
	}

	return uint32(duration / time.Second), nil
}
