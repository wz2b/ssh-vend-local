package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseTTLSeconds(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{name: "duration", input: "15m", want: 900},
		{name: "seconds", input: "3600", want: 3600},
		{name: "whitespace", input: "  1h  ", want: 3600},
		{name: "invalid", input: "abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTTLSeconds(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTTLSeconds(%q) = %d, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTTLSeconds(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("parseTTLSeconds(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveSigningKeyPath(t *testing.T) {
	privatePath, err := resolveSigningKeyPath("default")
	if err != nil {
		t.Fatalf("resolveSigningKeyPath default unexpected error: %v", err)
	}
	if privatePath != filepath.Join(defaultKeysDir, "default") {
		t.Fatalf("private path = %q, want %q", privatePath, filepath.Join(defaultKeysDir, "default"))
	}

	for _, name := range []string{"../evil", "bad/key", "bad key", "bad:key", "bad*key", ""} {
		if _, err := resolveSigningKeyPath(name); err == nil {
			t.Fatalf("resolveSigningKeyPath(%q) expected error", name)
		}
	}

	for _, name := range []string{"default", "lab-1", "team_ops", "prod.ca"} {
		if !validSigningKeyName(name) {
			t.Fatalf("validSigningKeyName(%q) = false, want true", name)
		}
	}
}

func TestCheckAccess(t *testing.T) {
	policy := strings.Join([]string{
		"# comment",
		"1000:ansadmin,deploy:default,lab:3600",
		"995:ansadmin:default:900",
	}, "\n") + "\n"

	policyPath := filepath.Join(t.TempDir(), "profiles")
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	t.Setenv("SUDO_UID", "1000")
	req := SigningRequest{Principal: "ansadmin", SigningKey: "default"}
	if err := checkAccess(policyPath, "1000", req, 900); err != nil {
		t.Fatalf("checkAccess allow unexpected error: %v", err)
	}

	if err := checkAccess(policyPath, "1000", req, 3601); err == nil {
		t.Fatalf("checkAccess denied TTL expected error")
	}

	badReq := SigningRequest{Principal: "root", SigningKey: "default"}
	if err := checkAccess(policyPath, "1000", badReq, 900); err == nil {
		t.Fatalf("checkAccess denied principal expected error")
	}
}

func TestCheckAccessMalformedLine(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "profiles")
	if err := os.WriteFile(policyPath, []byte("1000:ansadmin:default\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	t.Setenv("SUDO_UID", "1000")
	err := checkAccess(policyPath, "1000", SigningRequest{Principal: "ansadmin", SigningKey: "default"}, 900)
	if err == nil {
		t.Fatalf("expected malformed line error")
	}
}

func TestCheckSignerExecutionContext(t *testing.T) {
	currentUser, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatalf("lookup current user: %v", err)
	}
	if currentUser.Username != expectedSignerUser {
		t.Skip("current test environment does not run as ssh-vend-signer")
	}

	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_USER", "alice")

	ctx, err := checkSignerExecutionContext()
	if err != nil {
		t.Fatalf("execution-context check unexpected error: %v", err)
	}
	if ctx.CallerUID != "1000" || ctx.CallerUser != "alice" {
		t.Fatalf("context = %+v, want caller_uid=1000 caller_user=alice", ctx)
	}
}

func TestCheckSignerExecutionContextMissingEnv(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_USER", "alice")
	if _, err := checkSignerExecutionContext(); err == nil {
		t.Fatalf("expected missing SUDO_UID error")
	}

	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_USER", "")
	if _, err := checkSignerExecutionContext(); err == nil {
		t.Fatalf("expected missing SUDO_USER error")
	}
}

func TestCheckSignerExecutionContextEnforcesSignerUser(t *testing.T) {
	currentUser, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatalf("lookup current user: %v", err)
	}
	if currentUser.Username == expectedSignerUser {
		t.Skip("current test environment already runs as ssh-vend-signer")
	}

	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_USER", "alice")
	if _, err := checkSignerExecutionContext(); err == nil {
		t.Fatalf("expected effective-user enforcement error")
	}
}

func TestSignCertificateDefaultExtensions(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keySigner, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	privPath := filepath.Join(t.TempDir(), "default")
	privBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	req := SigningRequest{PublicKey: string(ssh.MarshalAuthorizedKey(keySigner.PublicKey())), Principal: "ansadmin", SigningKey: "default", Identity: "id"}
	line, err := signCertificate(req, privPath, 900)
	if err != nil {
		t.Fatalf("signCertificate: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse authorized key: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsed)
	}
	if len(cert.Permissions.Extensions) != 1 {
		t.Fatalf("extensions = %#v, want only permit-pty", cert.Permissions.Extensions)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Fatalf("extensions = %#v, want permit-pty", cert.Permissions.Extensions)
	}
}
