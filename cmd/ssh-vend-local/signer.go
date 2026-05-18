package main

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

const defaultSignerTimeout = 15 * time.Second

type SignEphemeralKeyRequest struct {
	// SignerCommand is the external signer command and arguments.
	//
	// Example:
	//
	//	[]string{
	//	    "sudo",
	//	    "-n",
	//	    "-u",
	//	    "ssh-vend-signer",
	//	    "/usr/local/libexec/ssh-vend-local-signer",
	//	}
	//
	// The signer receives JSON on stdin and must write the OpenSSH certificate
	// authorized-key line on stdout.
	SignerCommand []string

	// PublicAuthorizedKey is the ephemeral public key in authorized_keys format.
	//
	// Example:
	//
	//	ssh-ed25519 AAAAC3...
	PublicAuthorizedKey string

	// Profile is the signer-owned policy profile being requested.
	//
	// The unprivileged caller requests a profile. The privileged signer decides
	// what that profile means: signing key, principals, max TTL, extensions,
	// critical options, source-address restrictions, etc.
	Profile string

	// RequestedTTL is a request, not authority. The signer should clamp this to
	// the profile's maximum TTL.
	RequestedTTL string

	// Identity is used as the certificate key ID/comment. The signer may accept,
	// rewrite, sanitize, or ignore it according to policy.
	Identity string

	Verbose bool
}

type externalSignRequest struct {
	PublicKey    string `json:"public_key"`
	Profile      string `json:"profile"`
	RequestedTTL string `json:"requested_ttl,omitempty"`
	Identity     string `json:"identity,omitempty"`
}

// SignEphemeralKey asks an external signer process to sign an ephemeral public key.
//
// This function does not read the CA private key. The CA key is owned by the
// external signer process, usually launched through sudo as a dedicated signer
// user.
//
// Contract:
//
//	stdin:  JSON externalSignRequest
//	stdout: one OpenSSH certificate authorized-key line
//	stderr: diagnostics only
//
// The returned string is suitable for writing to:
//
//	id_ed25519-cert.pub
//	id_rsa-cert.pub
func SignEphemeralKey(req SignEphemeralKeyRequest) (string, error) {
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

	payload := externalSignRequest{
		PublicKey:    req.PublicAuthorizedKey,
		Profile:      req.Profile,
		RequestedTTL: req.RequestedTTL,
		Identity:     req.Identity,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal signing request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultSignerTimeout)
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
			return "", fmt.Errorf("signer timed out after %s: %w", defaultSignerTimeout, ctx.Err())
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
