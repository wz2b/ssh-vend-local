package signerprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultTimeout = 15 * time.Second

type Request struct {
	SignerCommand       []string
	PublicAuthorizedKey string
	Profile             string
	RequestedTTL        string
	Identity            string
	Principal           string
	Verbose             bool
}

type externalRequest struct {
	PublicKey    string `json:"public_key"`
	SigningKey   string `json:"signing_key"`
	RequestedTTL string `json:"requested_ttl,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Principal    string `json:"principal"`
}

func Sign(req Request) (string, error) {
	if len(req.SignerCommand) == 0 {
		return "", errors.New("signer command is required")
	}
	if strings.TrimSpace(req.SignerCommand[0]) == "" {
		return "", errors.New("signer command executable is required")
	}
	if strings.TrimSpace(req.PublicAuthorizedKey) == "" {
		return "", errors.New("public authorized key is required")
	}
	if strings.TrimSpace(req.Profile) == "" {
		return "", errors.New("profile is required")
	}

	payload := externalRequest{
		PublicKey:    req.PublicAuthorizedKey,
		RequestedTTL: req.RequestedTTL,
		Identity:     req.Identity,
		Principal:    req.Principal,
		SigningKey:   req.Profile,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal signing request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, req.SignerCommand[0], req.SignerCommand[1:]...)
	cmd.Stdin = bytes.NewReader(append(payloadBytes, '\n'))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if req.Verbose {
		fmt.Fprintf(os.Stderr, "ssh-vend-local: signer command: %s\n", strings.Join(req.SignerCommand, " "))
		fmt.Fprintf(os.Stderr, "ssh-vend-local: signer profile: %s\n", req.Profile)
	}

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("signer timed out after %s: %w", defaultTimeout, ctx.Err())
		}
		errText := strings.TrimSpace(stderr.String())
		if errText != "" {
			return "", fmt.Errorf("signer failed: %w: %s", err, errText)
		}
		return "", fmt.Errorf("signer failed: %w", err)
	}

	certLine := strings.TrimSpace(stdout.String())
	if certLine == "" {
		errText := strings.TrimSpace(stderr.String())
		if errText != "" {
			return "", fmt.Errorf("signer returned empty certificate; stderr: %s", errText)
		}
		return "", errors.New("signer returned empty certificate")
	}
	if !strings.HasPrefix(certLine, "ssh-") {
		return "", fmt.Errorf("signer returned invalid-looking SSH certificate line: %q", certLine)
	}

	return certLine + "\n", nil
}
