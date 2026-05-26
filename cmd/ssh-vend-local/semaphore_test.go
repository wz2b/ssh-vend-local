package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wz2b/ssh-vend-local/internal/sshvend/agentproto"
	"github.com/wz2b/ssh-vend-local/internal/sshvend/agentruntime"
	"github.com/wz2b/ssh-vend-local/internal/sshvend/semaphoreagent"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// ── helpers ──────────────────────────────────────────────────────────────────

type agentRequest = agentproto.Request
type agentResponse = agentproto.Response

func readAgentRequest(r *bufio.Reader) (*agentRequest, error) {
	return agentproto.ReadRequest(r)
}

func readAgentResponse(r *bufio.Reader) (*agentResponse, error) {
	return agentproto.ReadResponse(r)
}

func writeAgentResponse(w io.Writer, resp agentResponse) error {
	return agentproto.WriteResponse(w, resp)
}

func installSignerStub(t *testing.T, fn func(SignEphemeralKeyRequest) (string, error)) {
	t.Helper()
	old := agentruntime.SignFunc
	agentruntime.SignFunc = fn
	t.Cleanup(func() { agentruntime.SignFunc = old })
}

func makeSignerSuccessStub(t *testing.T, capture *SignEphemeralKeyRequest) func(SignEphemeralKeyRequest) (string, error) {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("create CA signer: %v", err)
	}

	return func(req SignEphemeralKeyRequest) (string, error) {
		if capture != nil {
			*capture = req
		}

		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicAuthorizedKey))
		if err != nil {
			return "", fmt.Errorf("parse public key: %w", err)
		}

		now := time.Now()
		cert := &ssh.Certificate{
			Key:             pub,
			Serial:          uint64(now.UnixNano()),
			CertType:        ssh.UserCert,
			KeyId:           req.Identity,
			ValidPrincipals: []string{req.Principal},
			ValidAfter:      uint64(now.Add(-15 * time.Second).Unix()),
			ValidBefore:     uint64(now.Add(15 * time.Minute).Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{},
				Extensions:      map[string]string{"permit-pty": ""},
			},
		}

		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			return "", fmt.Errorf("sign cert: %w", err)
		}

		return string(ssh.MarshalAuthorizedKey(cert)), nil
	}
}

// writeTestRequest encodes an AGENT/1 REQUEST and writes it to w.
func writeTestRequest(t *testing.T, w io.Writer, id, method string, body []byte) {
	t.Helper()
	hdr := fmt.Sprintf("AGENT/1 REQUEST\nId: %s\nMethod: %s\nContent-Length: %d\n\n",
		id, method, len(body))
	if _, err := io.WriteString(w, hdr); err != nil {
		t.Fatalf("write test request header: %v", err)
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			t.Fatalf("write test request body: %v", err)
		}
	}
}

// readTestResponse reads one AGENT/1 RESPONSE and fails the test on any error.
func readTestResponse(t *testing.T, r *bufio.Reader) *agentResponse {
	t.Helper()
	resp, err := readAgentResponse(r)
	if err != nil {
		t.Fatalf("read test response: %v", err)
	}
	return resp
}

func withStubSignerCommand(args []string) []string {
	has := func(name string) bool {
		for i := 0; i < len(args); i++ {
			if args[i] == name {
				return true
			}
		}
		return false
	}

	prefix := make([]string, 0, 8)
	if !has("-key-type") {
		prefix = append(prefix, "-key-type", "ed25519")
	}
	if !has("-signer-command") {
		prefix = append(prefix, "-signer-command", "stub-signer")
	}

	out := make([]string, 0, len(prefix)+len(args))
	out = append(out, prefix...)
	out = append(out, args...)
	return out
}

// ── unit tests ────────────────────────────────────────────────────────────────

func TestReadAgentRequest_Config(t *testing.T) {
	body := []byte("hello-world")
	raw := fmt.Sprintf("AGENT/1 REQUEST\nId: 42\nMethod: config\nContent-Length: %d\n\n%s",
		len(body), body)

	req, err := readAgentRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readAgentRequest: %v", err)
	}

	if req.ID != "42" {
		t.Errorf("ID = %q, want 42", req.ID)
	}
	if req.Method != "config" {
		t.Errorf("Method = %q, want config", req.Method)
	}
	if req.ContentLength != len(body) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
	if string(req.Body) != string(body) {
		t.Errorf("Body = %q, want %q", req.Body, body)
	}
}

func TestReadAgentRequest_Shutdown(t *testing.T) {
	raw := "AGENT/1 REQUEST\nId: 7\nMethod: shutdown\nContent-Length: 0\n\n"

	req, err := readAgentRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readAgentRequest: %v", err)
	}
	if req.Method != "shutdown" {
		t.Errorf("Method = %q, want shutdown", req.Method)
	}
	if req.ID != "7" {
		t.Errorf("ID = %q, want 7", req.ID)
	}
	if len(req.Body) != 0 {
		t.Errorf("Body should be empty, got %q", req.Body)
	}
}

func TestReadAgentRequest_WrongStartLine(t *testing.T) {
	raw := "HTTP/1.1 200 OK\n\n"
	_, err := readAgentRequest(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("expected error for wrong start line")
	}
}

func TestReadAgentRequest_EOF(t *testing.T) {
	_, err := readAgentRequest(bufio.NewReader(strings.NewReader("")))
	if err != io.EOF {
		t.Errorf("empty reader: err = %v, want io.EOF", err)
	}
}

func TestWriteAgentResponse_ContentLength(t *testing.T) {
	body := []byte("test-socket-path")
	var buf bytes.Buffer
	err := writeAgentResponse(&buf, agentResponse{
		ID:     "1",
		Status: 200,
		Body:   body,
	})
	if err != nil {
		t.Fatalf("writeAgentResponse: %v", err)
	}

	// Parse the written text and verify headers.
	out := buf.String()
	if !strings.HasPrefix(out, "AGENT/1 RESPONSE\n") {
		t.Errorf("response does not start with AGENT/1 RESPONSE: %q", out)
	}
	clLine := fmt.Sprintf("Content-Length: %d", len(body))
	if !strings.Contains(out, clLine) {
		t.Errorf("response does not contain %q; got:\n%s", clLine, out)
	}
	if !strings.HasSuffix(out, string(body)) {
		t.Errorf("response body not at end; got:\n%s", out)
	}
}

func TestWriteAgentResponse_DefaultMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = writeAgentResponse(&buf, agentResponse{ID: "1", Status: 200})
	if !strings.Contains(buf.String(), "Message: OK") {
		t.Error("200 response missing 'Message: OK'")
	}

	buf.Reset()
	_ = writeAgentResponse(&buf, agentResponse{ID: "1", Status: 500})
	if !strings.Contains(buf.String(), "Message: Error") {
		t.Error("500 response missing 'Message: Error'")
	}
}

func TestWriteAgentResponse_FlushesBufio(t *testing.T) {
	// Wrap a bytes.Buffer in bufio.Writer so we can verify Flush is called.
	var underlying bytes.Buffer
	bw := bufio.NewWriter(&underlying)

	err := writeAgentResponse(bw, agentResponse{ID: "1", Status: 200, Body: []byte("data")})
	if err != nil {
		t.Fatalf("writeAgentResponse: %v", err)
	}
	// If Flush was called, underlying has bytes; if not, it would be empty.
	if underlying.Len() == 0 {
		t.Error("writeAgentResponse did not flush bufio.Writer")
	}
}

// ── integration test ─────────────────────────────────────────────────────────

// TestSemaphoreAgentRoundTrip is a full end-to-end test:
//
//  1. Starts runSemaphoreAgent in a goroutine with injected stdin/stdout.
//  2. Sends an AGENT/1 config request and reads the 200 OK response.
//  3. Connects to the returned socket as an ssh-agent client.
//  4. Verifies at least one certificate identity is exposed.
//  5. Sends a shutdown request and reads the 200 OK.
//  6. Verifies the socket file is removed.
//  7. Verifies stdout contained only AGENT/1 RESPONSE messages.
func TestSemaphoreAgentRoundTrip(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))
	runtimeDir := t.TempDir()

	// Pipes that stand in for stdin and stdout.
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	var logBuf bytes.Buffer

	// Run the agent in a goroutine, capturing its return value.
	agentErrC := make(chan error, 1)
	go func() {
		agentErrC <- runSemaphoreAgent(
			withStubSignerCommand([]string{
				"-principal", "ansible",
				"-ttl", "15m",
				"-runtime-dir", runtimeDir,
				"-debug",
			}),
			stdinR,
			stdoutW,
			&logBuf,
		)
	}()

	select {
	case err := <-agentErrC:
		t.Fatalf("runSemaphoreAgent returned before config request: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Capture all bytes written to stdout so we can verify later.
	var stdoutCapture bytes.Buffer
	stdoutRdr := bufio.NewReader(io.TeeReader(stdoutR, &stdoutCapture))

	// ── send config request ───────────────────────────────────────────────
	configBody := []byte(`{"note":"test config"}`)
	writeTestRequest(t, stdinW, "1", "config", configBody)

	// ── read config response ──────────────────────────────────────────────
	configResp := readTestResponse(t, stdoutRdr)
	if configResp.Status != 200 {
		t.Fatalf("config response status = %d, want 200; body: %s",
			configResp.Status, configResp.Body)
	}
	socketPath := strings.TrimSpace(string(configResp.Body))
	if socketPath == "" {
		t.Fatal("config response body (socket path) is empty")
	}

	// Socket file must exist at this point.
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket does not exist after config response: %v", err)
	}

	// ── connect as an ssh-agent client ────────────────────────────────────
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		t.Fatalf("dial agent socket %s: %v", socketPath, err)
	}
	client := sshagent.NewClient(conn)
	// conn is closed explicitly below (before waiting for agent to exit) so the
	// agent's serveWG.Wait() can return promptly during shutdown.

	// ── list identities and verify at least one certificate ───────────────
	keys, err := client.List()
	if err != nil {
		t.Fatalf("agent List: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("agent returned zero identities")
	}

	var foundCert bool
	for _, k := range keys {
		// When an AddedKey.Certificate is set, the agent lists the cert's
		// public key type, which contains "cert-v01" for OpenSSH certificates.
		if strings.Contains(k.Type(), "cert") {
			foundCert = true
			break
		}
		// Fallback: parse the key blob to check for *ssh.Certificate.
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err == nil {
			if _, ok := pub.(*ssh.Certificate); ok {
				foundCert = true
				break
			}
		}
	}
	if !foundCert {
		t.Errorf("no certificate identity found in agent; keys = %v", keys)
	}

	// ── agent must not return before shutdown is sent ─────────────────────
	select {
	case err := <-agentErrC:
		t.Fatalf("runSemaphoreAgent returned early (err=%v)", err)
	default:
		// Good: agent is still running.
	}

	// ── send shutdown request ─────────────────────────────────────────────
	// Close the agent connection first so the agent's serveWG.Wait() can
	// complete once it receives the shutdown request.
	if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "use of closed") {
		t.Logf("conn.Close: %v", err)
	}

	writeTestRequest(t, stdinW, "2", "shutdown", nil)

	// ── read shutdown response ────────────────────────────────────────────
	shutdownResp := readTestResponse(t, stdoutRdr)
	if shutdownResp.Status != 200 {
		t.Fatalf("shutdown response status = %d, want 200; body: %s",
			shutdownResp.Status, shutdownResp.Body)
	}

	// Close the stdin pipe so the agent can unblock if needed.
	_ = stdinW.Close()
	_ = stdoutW.Close()

	// Wait for the agent goroutine to exit.
	select {
	case err := <-agentErrC:
		if err != nil {
			t.Errorf("runSemaphoreAgent returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runSemaphoreAgent did not exit within 5 s after shutdown")
	}

	// ── socket must be removed after shutdown ─────────────────────────────
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket %s should be removed after shutdown, stat err = %v", socketPath, err)
	}

	// ── stdout contained only AGENT/1 RESPONSE messages ───────────────────
	// We already drained stdoutRdr above; check that every non-empty block
	// starts with "AGENT/1 RESPONSE".
	verifyOnlyAgentResponses(t, stdoutCapture.Bytes())
}

// verifyOnlyAgentResponses checks that data consists solely of AGENT/1 RESPONSE
// framed messages (no stray bytes, log lines, etc.).
func verifyOnlyAgentResponses(t *testing.T, data []byte) {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(data))
	count := 0
	for {
		resp, err := readAgentResponse(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("stdout parse error at message %d: %v\nraw stdout:\n%s", count, err, data)
			return
		}
		_ = resp
		count++
	}
	if count == 0 {
		t.Error("stdout was empty; expected at least one AGENT/1 RESPONSE")
	}
}

// TestSemaphoreAgentBadProfile verifies that an unconfigured profile produces
// a non-200 AGENT/1 RESPONSE on stdout and a non-nil error return.
func TestSemaphoreAgentBadProfile(t *testing.T) {
	fallback := makeSignerSuccessStub(t, nil)
	installSignerStub(t, func(req SignEphemeralKeyRequest) (string, error) {
		if req.Profile == "nonexistent-profile-xyz" {
			return "", fmt.Errorf("unknown profile %q", req.Profile)
		}
		return fallback(req)
	})

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	agentErrC := make(chan error, 1)
	go func() {
		agentErrC <- runSemaphoreAgent(
			withStubSignerCommand([]string{"-profile", "nonexistent-profile-xyz", "-principal", "ansible"}),
			stdinR, stdoutW, io.Discard,
		)
	}()

	go func() {
		writeTestRequest(t, stdinW, "1", "config", nil)
	}()

	r := bufio.NewReader(stdoutR)
	resp, err := readAgentResponse(r)
	_ = stdoutW.Close()
	_ = stdinW.Close()

	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if resp.Status == 200 {
		t.Errorf("expected non-200 for unconfigured profile, got status %d", resp.Status)
	}

	// Agent must also return a non-nil error.
	select {
	case agentErr := <-agentErrC:
		if agentErr == nil {
			t.Error("expected non-nil error from runSemaphoreAgent with unconfigured profile")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runSemaphoreAgent did not exit after config failure")
	}
}

// TestSemaphoreAgentMissingPrincipal verifies the 400 path when -principal is omitted.
func TestSemaphoreAgentMissingPrincipal(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		_ = runSemaphoreAgent(
			withStubSignerCommand([]string{}),
			stdinR, stdoutW, io.Discard,
		)
		_ = stdoutW.Close()
	}()

	go func() {
		writeTestRequest(t, stdinW, "1", "config", nil)
		_ = stdinW.Close()
	}()

	r := bufio.NewReader(stdoutR)
	resp, err := readAgentResponse(r)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if resp.Status != 400 {
		t.Errorf("expected 400 for missing principal, got %d", resp.Status)
	}
}

// ── Content-Length required tests ─────────────────────────────────────────────

func TestReadAgentRequest_MissingContentLength(t *testing.T) {
	// No Content-Length header at all.
	raw := "AGENT/1 REQUEST\nId: 1\nMethod: config\n\n"
	_, err := readAgentRequest(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("expected error for missing Content-Length")
	}
	if !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("error should mention Content-Length, got: %v", err)
	}
}

func TestReadAgentRequest_NegativeContentLength(t *testing.T) {
	raw := "AGENT/1 REQUEST\nId: 1\nMethod: config\nContent-Length: -1\n\n"
	_, err := readAgentRequest(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("expected error for negative Content-Length")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("error should mention negative, got: %v", err)
	}
}

func TestReadAgentResponse_MissingContentLength(t *testing.T) {
	raw := "AGENT/1 RESPONSE\nId: 1\nStatus: 200\nMessage: OK\n\n"
	_, err := readAgentResponse(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("expected error for missing Content-Length in response")
	}
	if !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("error should mention Content-Length, got: %v", err)
	}
}

func TestReadAgentResponse_NegativeContentLength(t *testing.T) {
	raw := "AGENT/1 RESPONSE\nId: 1\nStatus: 200\nMessage: OK\nContent-Length: -5\n\n"
	_, err := readAgentResponse(bufio.NewReader(strings.NewReader(raw)))
	if err == nil {
		t.Fatal("expected error for negative Content-Length in response")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("error should mention negative, got: %v", err)
	}
}

// ── Case-insensitive header tests ─────────────────────────────────────────────

func TestReadAgentRequest_CaseInsensitiveHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"exact canonical", "AGENT/1 REQUEST\nId: 1\nMethod: config\nContent-Length: 0\n\n"},
		{"no space after colon", "AGENT/1 REQUEST\nId:1\nMethod:config\nContent-Length:0\n\n"},
		{"lowercase content-length", "AGENT/1 REQUEST\nId: 1\nMethod: config\ncontent-length: 0\n\n"},
		{"uppercase CONTENT-LENGTH", "AGENT/1 REQUEST\nId: 1\nMethod: config\nCONTENT-LENGTH: 0\n\n"},
		{"mixed case Id and Method", "AGENT/1 REQUEST\nid: 1\nMETHOD: config\nContent-Length: 0\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readAgentRequest(bufio.NewReader(strings.NewReader(tc.raw)))
			if err != nil {
				t.Fatalf("readAgentRequest: %v", err)
			}
			if req.ContentLength != 0 {
				t.Errorf("ContentLength = %d, want 0", req.ContentLength)
			}
			if req.Method != "config" {
				t.Errorf("Method = %q, want config", req.Method)
			}
		})
	}
}

func TestReadAgentResponse_CaseInsensitiveHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"lowercase content-length", "AGENT/1 RESPONSE\nId: 1\nStatus: 200\nMessage: OK\ncontent-length: 0\n\n"},
		{"CONTENT-LENGTH uppercase", "AGENT/1 RESPONSE\nId: 1\nStatus: 200\nMessage: OK\nCONTENT-LENGTH: 0\n\n"},
		{"no space after colon", "AGENT/1 RESPONSE\nId:1\nStatus:200\nMessage:OK\nContent-Length:0\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := readAgentResponse(bufio.NewReader(strings.NewReader(tc.raw)))
			if err != nil {
				t.Fatalf("readAgentResponse: %v", err)
			}
			if resp.Status != 200 {
				t.Errorf("Status = %d, want 200", resp.Status)
			}
		})
	}
}

// ── JSON config parsing unit tests ────────────────────────────────────────────

func TestParseJSONConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		want    semaphoreagent.JSONConfig
		wantErr bool
	}{
		{"empty body", "", semaphoreagent.JSONConfig{}, false},
		{"whitespace only", "   \n  ", semaphoreagent.JSONConfig{}, false},
		{"empty object", "{}", semaphoreagent.JSONConfig{}, false},
		{"all fields", `{"profile":"p","principal":"u","ttl":"1h"}`,
			semaphoreagent.JSONConfig{Profile: "p", Principal: "u", TTL: "1h"}, false},
		{"partial fields", `{"principal":"ansible"}`,
			semaphoreagent.JSONConfig{Principal: "ansible"}, false},
		{"invalid json", "not-json", semaphoreagent.JSONConfig{}, true},
		{"ca_key rejected", `{"ca_key":"/tmp/key"}`, semaphoreagent.JSONConfig{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := semaphoreagent.ParseJSONConfig([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// ── JSON config overlay integration tests ─────────────────────────────────────

// runAgentOneShot sends a config request, reads the response, then sends shutdown.
// Returns the config response.  Cleans up the agent goroutine before returning.
func runAgentOneShot(t *testing.T, agentArgs []string, configBody []byte) *agentResponse {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	agentErrC := make(chan error, 1)
	go func() {
		agentErrC <- runSemaphoreAgent(withStubSignerCommand(agentArgs), stdinR, stdoutW, io.Discard)
	}()

	r := bufio.NewReader(stdoutR)
	writeTestRequest(t, stdinW, "1", "config", configBody)
	resp := readTestResponse(t, r)

	if resp.Status == 200 {
		// Send shutdown to let the agent exit cleanly.
		writeTestRequest(t, stdinW, "2", "shutdown", nil)
		_, _ = readAgentResponse(r)
	}

	_ = stdinW.Close()
	_ = stdoutW.Close()

	select {
	case <-agentErrC:
	case <-time.After(5 * time.Second):
		t.Fatal("runSemaphoreAgent did not exit within 5 s")
	}
	return resp
}

func TestJSONConfigOverlay_PrincipalFromJSON(t *testing.T) {
	var captured SignEphemeralKeyRequest
	installSignerStub(t, makeSignerSuccessStub(t, &captured))
	runtimeDir := t.TempDir()

	// No -principal flag; principal must come from JSON.
	resp := runAgentOneShot(t,
		[]string{"-runtime-dir", runtimeDir},
		[]byte(`{"principal":"from-json"}`),
	)
	if resp.Status != 200 {
		t.Fatalf("expected 200 with principal from JSON, got %d body: %s", resp.Status, resp.Body)
	}
	if captured.Principal != "from-json" {
		t.Fatalf("principal sent to signer = %q, want %q", captured.Principal, "from-json")
	}
}

func TestJSONConfigOverlay_ProfileFromJSON(t *testing.T) {
	testProfile := "test-profile-" + t.Name()
	var captured SignEphemeralKeyRequest
	installSignerStub(t, makeSignerSuccessStub(t, &captured))
	runtimeDir := t.TempDir()

	// Profile comes from JSON, not CLI flag.
	resp := runAgentOneShot(t,
		[]string{"-principal", "ansible", "-runtime-dir", runtimeDir},
		[]byte(`{"profile":"`+testProfile+`"}`),
	)
	if resp.Status != 200 {
		t.Fatalf("profile from JSON should work; got %d body: %s", resp.Status, resp.Body)
	}
	if captured.Profile != testProfile {
		t.Fatalf("profile sent to signer = %q, want %q", captured.Profile, testProfile)
	}
}

func TestJSONConfigOverlay_JSONCAKeyIsRejected(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))
	runtimeDir := t.TempDir()

	// JSON includes a ca_key field, which is not part of the external-agent contract.
	resp := runAgentOneShot(t,
		[]string{"-principal", "ansible", "-runtime-dir", runtimeDir},
		[]byte(`{"ca_key":"/nonexistent/should-be-ignored"}`),
	)
	if resp.Status != 400 {
		t.Fatalf("ca_key in JSON config should be rejected; got %d body: %s", resp.Status, resp.Body)
	}
}

func TestJSONConfigOverlay_TTLFromJSON(t *testing.T) {
	var captured SignEphemeralKeyRequest
	installSignerStub(t, makeSignerSuccessStub(t, &captured))
	runtimeDir := t.TempDir()

	resp := runAgentOneShot(t,
		[]string{"-principal", "ansible", "-runtime-dir", runtimeDir},
		[]byte(`{"ttl":"30m"}`),
	)
	if resp.Status != 200 {
		t.Fatalf("ttl from JSON should work; got %d body: %s", resp.Status, resp.Body)
	}
	if captured.RequestedTTL != "30m" {
		t.Fatalf("ttl sent to signer = %q, want %q", captured.RequestedTTL, "30m")
	}
}

func TestJSONConfigOverlay_CLIOverridesJSONPrincipal(t *testing.T) {
	var captured SignEphemeralKeyRequest
	installSignerStub(t, makeSignerSuccessStub(t, &captured))
	runtimeDir := t.TempDir()

	// CLI -principal takes precedence over JSON principal.
	resp := runAgentOneShot(t,
		[]string{
			"-principal", "cli-principal",
			"-runtime-dir", runtimeDir,
		},
		[]byte(`{"principal":"json-principal"}`),
	)
	if resp.Status != 200 {
		t.Fatalf("CLI -principal should override JSON principal; got %d body: %s", resp.Status, resp.Body)
	}
	if captured.Principal != "cli-principal" {
		t.Fatalf("principal sent to signer = %q, want %q", captured.Principal, "cli-principal")
	}
}

func TestJSONConfigOverlay_CLIOverridesJSONTTL(t *testing.T) {
	var captured SignEphemeralKeyRequest
	installSignerStub(t, makeSignerSuccessStub(t, &captured))
	runtimeDir := t.TempDir()

	resp := runAgentOneShot(t,
		[]string{"-principal", "ansible", "-ttl", "45m", "-runtime-dir", runtimeDir},
		[]byte(`{"ttl":"30m"}`),
	)
	if resp.Status != 200 {
		t.Fatalf("CLI -ttl should override JSON ttl; got %d body: %s", resp.Status, resp.Body)
	}
	if captured.RequestedTTL != "45m" {
		t.Fatalf("ttl sent to signer = %q, want %q", captured.RequestedTTL, "45m")
	}
}

func TestJSONConfigOverlay_EmptyBodyAndEmptyJSON(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"nil body", nil},
		{"empty json", []byte("{}")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtimeDir := t.TempDir()
			resp := runAgentOneShot(t,
				[]string{"-principal", "ansible", "-runtime-dir", runtimeDir},
				tc.body,
			)
			if resp.Status != 200 {
				t.Fatalf("%s: expected 200, got %d body: %s", tc.name, resp.Status, resp.Body)
			}
		})
	}
}

func TestJSONConfigOverlay_InvalidJSON(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))
	runtimeDir := t.TempDir()

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	agentErrC := make(chan error, 1)
	go func() {
		agentErrC <- runSemaphoreAgent(
			withStubSignerCommand([]string{"-principal", "ansible", "-runtime-dir", runtimeDir}),
			stdinR, stdoutW, io.Discard,
		)
		_ = stdoutW.Close()
	}()

	r := bufio.NewReader(stdoutR)
	writeTestRequest(t, stdinW, "1", "config", []byte("not-json{{{"))
	resp, err := readAgentResponse(r)
	_ = stdinW.Close()

	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Status != 400 {
		t.Errorf("expected 400 for invalid JSON body, got %d", resp.Status)
	}

	select {
	case <-agentErrC:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not exit after config failure")
	}
}

// ── Stale socket tests ────────────────────────────────────────────────────────

func TestBuildSemaphoreRuntime_StaleSocketReplaced(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))
	runtimeDir := t.TempDir()
	socketPath := filepath.Join(runtimeDir, "agent.sock")

	// Simulate a stale socket left by a crashed process.  We use syscall.Bind
	// directly so that closing the fd does NOT unlink the file (unlike
	// net.Listener.Close() which auto-removes Unix sockets).
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create socket fd: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		syscall.Close(fd) //nolint:errcheck
		t.Fatalf("bind socket: %v", err)
	}
	syscall.Close(fd) //nolint:errcheck – file remains on disk

	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("stale socket not present before test: %v", err)
	}

	rt, err := agentruntime.Build(agentruntime.RuntimeArgs{
		SignerCommand: []string{"stub-signer"},
		KeyType:       "ed25519",
		Profile:       "default",
		Principal:     "test",
		RequestedTTL:  "15m",
		Identity:      "test-stale-replace",
		RuntimeDir:    runtimeDir,
		TTLSeconds:    900,
		Logw:          io.Discard,
	})
	if err != nil {
		t.Fatalf("buildSemaphoreRuntime should succeed with stale socket: %v", err)
	}
	_ = rt.Close()
}

func TestBuildSemaphoreRuntime_NonSocketFileIsError(t *testing.T) {
	installSignerStub(t, makeSignerSuccessStub(t, nil))
	runtimeDir := t.TempDir()
	socketPath := filepath.Join(runtimeDir, "agent.sock")

	// Create a regular file at the socket path.
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake file: %v", err)
	}

	_, err := agentruntime.Build(agentruntime.RuntimeArgs{
		SignerCommand: []string{"stub-signer"},
		KeyType:       "ed25519",
		Profile:       "default",
		Principal:     "test",
		RequestedTTL:  "15m",
		Identity:      "test-non-socket",
		RuntimeDir:    runtimeDir,
		TTLSeconds:    900,
		Logw:          io.Discard,
	})
	if err == nil {
		t.Fatal("expected error when non-socket file exists at socket path")
	}
	if !strings.Contains(err.Error(), "not a Unix socket") {
		t.Errorf("error should mention 'not a Unix socket', got: %v", err)
	}
}
