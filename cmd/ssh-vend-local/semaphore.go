package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// agentRequest is a parsed AGENT/1 REQUEST message.
type agentRequest struct {
	ID            string
	Method        string
	ContentLength int
	Body          []byte
}

// agentResponse is an AGENT/1 RESPONSE message.
type agentResponse struct {
	ID      string
	Status  int
	Message string
	Body    []byte
}

// parseHeaderKV splits a header line on the first colon, trims whitespace from
// both the key and the value, and returns them.  Header names are compared
// case-insensitively by callers (strings.EqualFold).
//
// Accepted forms:
//
//	Content-Length: 2
//	Content-Length:2
//	content-length: 2
//	CONTENT-LENGTH: 2
func parseHeaderKV(line string) (key, value string, err error) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("malformed header line: %q", line)
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), nil
}

// normalizeSingleDashLongFlags rewrites -long-form arguments to --long-form so
// semaphore-agent remains compatible with existing single-dash usage while using pflag.
func normalizeSingleDashLongFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") || len(arg) <= 2 {
			out = append(out, arg)
			continue
		}
		out = append(out, "--"+strings.TrimPrefix(arg, "-"))
	}
	return out
}

// readAgentRequest reads one AGENT/1 REQUEST from r.
// Returns io.EOF when the stream closes before the start line.
// Content-Length is required; missing or negative values are an error.
func readAgentRequest(r *bufio.Reader) (*agentRequest, error) {
	startLine, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && startLine == "" {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read start line: %w", err)
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	if startLine != "AGENT/1 REQUEST" {
		return nil, fmt.Errorf("expected 'AGENT/1 REQUEST', got %q", startLine)
	}

	req := &agentRequest{}
	hasContentLength := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // blank line terminates headers
		}
		key, value, err := parseHeaderKV(line)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key, "id"):
			req.ID = value
		case strings.EqualFold(key, "method"):
			req.Method = value
		case strings.EqualFold(key, "content-length"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Content-Length %q: %w", value, err)
			}
			if n < 0 {
				return nil, fmt.Errorf("Content-Length %d is negative", n)
			}
			req.ContentLength = n
			hasContentLength = true
		}
	}

	if !hasContentLength {
		return nil, fmt.Errorf("missing required Content-Length header in request")
	}

	if req.ContentLength > 0 {
		req.Body = make([]byte, req.ContentLength)
		if _, err := io.ReadFull(r, req.Body); err != nil {
			return nil, fmt.Errorf("read %d-byte request body: %w", req.ContentLength, err)
		}
	}

	return req, nil
}

// readAgentResponse reads one AGENT/1 RESPONSE from r.
// Used in tests and in the signer loop.
// Content-Length is required; missing or negative values are an error.
func readAgentResponse(r *bufio.Reader) (*agentResponse, error) {
	startLine, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && startLine == "" {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read response start line: %w", err)
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	if startLine != "AGENT/1 RESPONSE" {
		return nil, fmt.Errorf("expected 'AGENT/1 RESPONSE', got %q", startLine)
	}

	resp := &agentResponse{}
	contentLength := 0
	hasContentLength := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read response header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // blank line terminates headers; body follows
		}
		key, value, err := parseHeaderKV(line)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key, "id"):
			resp.ID = value
		case strings.EqualFold(key, "status"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Status %q: %w", value, err)
			}
			resp.Status = n
		case strings.EqualFold(key, "message"):
			resp.Message = value
		case strings.EqualFold(key, "content-length"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Content-Length %q: %w", value, err)
			}
			if n < 0 {
				return nil, fmt.Errorf("Content-Length %d is negative", n)
			}
			contentLength = n
			hasContentLength = true
		}
	}

	if !hasContentLength {
		return nil, fmt.Errorf("missing required Content-Length header in response")
	}

	if contentLength > 0 {
		resp.Body = make([]byte, contentLength)
		if _, err := io.ReadFull(r, resp.Body); err != nil {
			return nil, fmt.Errorf("read %d-byte response body: %w", contentLength, err)
		}
	}

	return resp, nil
}

// writeAgentResponse writes one AGENT/1 RESPONSE to w.
// It flushes w if w is a *bufio.Writer.
func writeAgentResponse(w io.Writer, resp agentResponse) error {
	msg := resp.Message
	if msg == "" {
		if resp.Status == 200 {
			msg = "OK"
		} else {
			msg = "Error"
		}
	}

	header := fmt.Sprintf("AGENT/1 RESPONSE\nId: %s\nStatus: %d\nMessage: %s\nContent-Length: %d\n\n",
		resp.ID, resp.Status, msg, len(resp.Body))

	if _, err := io.WriteString(w, header); err != nil {
		return fmt.Errorf("write response header: %w", err)
	}
	if len(resp.Body) > 0 {
		if _, err := w.Write(resp.Body); err != nil {
			return fmt.Errorf("write response body: %w", err)
		}
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// agentJSONConfig holds optional JSON fields from the AGENT/1 config request body.
// Semaphore supplies profile, principal, and ttl.
// The CA/signing backend is chosen internally based on profile; CA key paths are not part of the Semaphore contract.
// All fields are optional; absent or zero-value fields are ignored during overlay.
type agentJSONConfig struct {
	Profile   string `json:"profile"`
	Principal string `json:"principal"`
	TTL       string `json:"ttl"`
}

var signEphemeralKeyFunc = SignEphemeralKey

// parseJSONConfig parses an optional JSON config from body.
// An empty or whitespace-only body and a bare {} are both accepted and return
// a zero agentJSONConfig without error.
func parseJSONConfig(body []byte) (agentJSONConfig, error) {
	var cfg agentJSONConfig
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return cfg, nil
	}

	// Reject CA key path input explicitly; external-agent contract is profile/principal/ttl only.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return cfg, fmt.Errorf("parse JSON config body: %w", err)
	}
	if _, ok := fields["ca_key"]; ok {
		return cfg, fmt.Errorf("config field %q is not supported; CA selection is profile-based", "ca_key")
	}

	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		return cfg, fmt.Errorf("parse JSON config body: %w", err)
	}
	return cfg, nil
}

// cmdSemaphoreAgent is the entry point for "ssh-vend-local semaphore-agent".
func cmdSemaphoreAgent(args []string) error {
	return runSemaphoreAgent(args, os.Stdin, os.Stdout, os.Stderr)
}

// runSemaphoreAgent implements the AGENT/1 protocol over stdin/stdout/logw.
// It is separate from cmdSemaphoreAgent so tests can inject their own io.Reader/Writer.
//
// Semaphore supplies profile, principal, and ttl via AGENT/1 config JSON or CLI flags.
// The CA/signing backend is resolved internally from the profile; CA key paths
// are not part of the external-agent contract.
func runSemaphoreAgent(args []string, stdin io.Reader, stdout io.Writer, logw io.Writer) error {
	fs := pflag.NewFlagSet("semaphore-agent", pflag.ContinueOnError)
	fs.SetOutput(logw)
	registerCommonFlags(fs)
	debugFlag := fs.Bool("debug", false, "Enable debug log output")

	if err := fs.Parse(normalizeSingleDashLongFlags(args)); err != nil {
		return err
	}

	// Record which flags were explicitly supplied by the caller.
	// Used to implement CLI flag > JSON config > default precedence.
	visited := make(map[string]bool)
	fs.Visit(func(f *pflag.Flag) { visited[f.Name] = true })

	logf := func(format string, a ...any) {
		if *debugFlag {
			fmt.Fprintf(logw, "semaphore-agent: "+format+"\n", a...)
		}
	}

	// stdout is reserved for AGENT/1 framed responses only.
	bw := bufio.NewWriter(stdout)
	in := bufio.NewReader(stdin)

	// ── Step 1: read config request ────────────────────────────────────────
	configReq, err := readAgentRequest(in)
	if err != nil {
		return fmt.Errorf("read config request: %w", err)
	}
	if configReq.Method != "config" {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte(fmt.Sprintf("expected Method: config, got %q", configReq.Method)),
		})
		return fmt.Errorf("expected Method: config, got %q", configReq.Method)
	}
	logf("received config request (body %d bytes)", len(configReq.Body))

	cfg, err := LoadConfig(fs)
	if err != nil {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  500,
			Message: "Internal Error",
			Body:    []byte(fmt.Sprintf("load config: %v", err)),
		})
		return err
	}

	principalFlag, _ := fs.GetString("principal")

	// ── Step 2: apply JSON config overlay ──────────────────────────────────
	// Precedence: explicitly supplied CLI flag > JSON config value > default.
	jsonCfg, err := parseJSONConfig(configReq.Body)
	if err != nil {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte(err.Error()),
		})
		return err
	}

	effectiveProfile := cfg.Profile
	if !visited["profile"] && jsonCfg.Profile != "" {
		effectiveProfile = jsonCfg.Profile
	}
	effectivePrincipal := principalFlag
	if !visited["principal"] && jsonCfg.Principal != "" {
		effectivePrincipal = jsonCfg.Principal
	}
	effectiveTTL := cfg.TTL
	if !visited["ttl"] && jsonCfg.TTL != "" {
		effectiveTTL = jsonCfg.TTL
	}

	logf("effective config: profile=%s principal=%s ttl=%s runtime-dir=%q",
		effectiveProfile, effectivePrincipal, effectiveTTL, cfg.RuntimeDir)

	// ── Step 3: validate parameters ───────────────────────────────────────
	principalStr := strings.TrimSpace(effectivePrincipal)
	if principalStr == "" {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte("principal is required (use -principal flag or JSON config field)"),
		})
		return fmt.Errorf("principal is required")
	}

	ttlSecs, err := lifetimeSeconds(effectiveTTL)
	if err != nil {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte(fmt.Sprintf("invalid ttl %q: %v", effectiveTTL, err)),
		})
		return fmt.Errorf("parse ttl: %w", err)
	}
	if ttlSecs == 0 {
		ttlSecs = 900 // default 15m
	}

	// ── Step 4: build runtime (generate key, sign cert, start socket) ─────
	identity := cfg.Identity
	if identity == "" {
		identity = fmt.Sprintf("ssh-vend-local-%s-%d", principalStr, time.Now().Unix())
	}
	runtime, err := buildSemaphoreRuntime(semaphoreRuntimeArgs{
		signerCommand: cfg.SignerCommand,
		keyType:       cfg.KeyType,
		profile:       effectiveProfile,
		principal:     principalStr,
		requestedTTL:  effectiveTTL,
		identity:      identity,
		runtimeDir:    cfg.RuntimeDir,
		ttlSecs:       ttlSecs,
		verbose:       cfg.Verbose,
		debug:         *debugFlag,
		logw:          logw,
	})
	if err != nil {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      configReq.ID,
			Status:  500,
			Message: "Internal Error",
			Body:    []byte(err.Error()),
		})
		return fmt.Errorf("build agent runtime: %w", err)
	}
	logf("agent socket ready: %s", runtime.SocketPath)

	// ── Step 5: send 200 OK with socket path ───────────────────────────────
	if err := writeAgentResponse(bw, agentResponse{
		ID:     configReq.ID,
		Status: 200,
		Body:   []byte(runtime.SocketPath),
	}); err != nil {
		_ = runtime.Close()
		return fmt.Errorf("write config response: %w", err)
	}

	// ── Step 6: wait for shutdown request ─────────────────────────────────
	logf("waiting for shutdown request")
	shutdownReq, err := readAgentRequest(in)
	if err != nil {
		_ = runtime.Close()
		if errors.Is(err, io.EOF) {
			logf("stdin closed; shutting down without explicit shutdown request")
			return nil
		}
		return fmt.Errorf("read shutdown request: %w", err)
	}
	if shutdownReq.Method != "shutdown" {
		_ = writeAgentResponse(bw, agentResponse{
			ID:      shutdownReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte(fmt.Sprintf("expected Method: shutdown, got %q", shutdownReq.Method)),
		})
		_ = runtime.Close()
		return fmt.Errorf("expected Method: shutdown, got %q", shutdownReq.Method)
	}

	// ── Step 7: graceful shutdown ──────────────────────────────────────────
	logf("shutdown requested")
	if err := runtime.Close(); err != nil {
		logf("runtime close error: %v", err)
	}

	if err := writeAgentResponse(bw, agentResponse{
		ID:     shutdownReq.ID,
		Status: 200,
	}); err != nil {
		return fmt.Errorf("write shutdown response: %w", err)
	}

	logf("shutdown complete")
	return nil
}

// semaphoreRuntimeArgs holds parameters for buildSemaphoreRuntime.
type semaphoreRuntimeArgs struct {
	signerCommand []string
	keyType       string
	profile       string
	principal     string
	requestedTTL  string
	identity      string
	runtimeDir    string
	ttlSecs       uint32
	verbose       bool
	debug         bool
	logw          io.Writer
}

// buildSemaphoreRuntime generates an ephemeral keypair, asks the configured signer
// to sign it as an SSH user certificate, creates a Unix-domain socket, and serves
// the ssh-agent protocol over that socket.
//
// The signer command owns profile policy and signing backend selection.
// Private key material is kept entirely in memory. The only filesystem objects
// created are the socket directory and the socket file itself.
func buildSemaphoreRuntime(args semaphoreRuntimeArgs) (*EphemeralAgentRuntime, error) {
	keyPair, err := genEphemeralKeypair(args.keyType)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	certLine, err := signEphemeralKeyFunc(SignEphemeralKeyRequest{
		SignerCommand:       args.signerCommand,
		PublicAuthorizedKey: keyPair.PubAuth,
		Principal:           args.principal,
		Profile:             args.profile,
		RequestedTTL:        args.requestedTTL,
		Identity:            args.identity,
		Verbose:             args.verbose || args.debug,
	})
	if err != nil {
		return nil, fmt.Errorf("sign ephemeral key: %w", err)
	}

	cert, err := parseCertificateLine(certLine)
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(keyPair.PrivPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral private key: %w", err)
	}

	// Create the runtime directory that holds the socket.
	socketDir := args.runtimeDir
	ownedDir := false
	if socketDir == "" {
		socketDir, err = os.MkdirTemp("", "ssh-vend-local-semaphore-*")
		if err != nil {
			return nil, fmt.Errorf("create runtime directory: %w", err)
		}
		ownedDir = true
	} else {
		if err := os.MkdirAll(socketDir, 0o700); err != nil {
			return nil, fmt.Errorf("create runtime directory %s: %w", socketDir, err)
		}
		if err := os.Chmod(socketDir, 0o700); err != nil {
			return nil, fmt.Errorf("chmod runtime directory %s: %w", socketDir, err)
		}
	}

	socketPath := filepath.Join(socketDir, "agent.sock")

	// Handle a stale socket file left by a previous crash or run.
	//   - If a Unix socket already exists at socketPath, remove it so we can rebind.
	//   - If a non-socket file exists, return an error rather than silently clobbering it.
	if lstatInfo, lstatErr := os.Lstat(socketPath); lstatErr == nil {
		if lstatInfo.Mode()&os.ModeSocket != 0 {
			// Stale socket: safe to remove and replace.
			if err := os.Remove(socketPath); err != nil {
				if ownedDir {
					_ = os.RemoveAll(socketDir)
				}
				return nil, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
			}
		} else {
			// Not a socket: something unexpected is at this path; refuse to proceed.
			if ownedDir {
				_ = os.RemoveAll(socketDir)
			}
			return nil, fmt.Errorf("socket path %s exists but is not a Unix socket (mode=%v)", socketPath, lstatInfo.Mode())
		}
	} else if !os.IsNotExist(lstatErr) {
		if ownedDir {
			_ = os.RemoveAll(socketDir)
		}
		return nil, fmt.Errorf("lstat socket path %s: %w", socketPath, lstatErr)
	}

	// Populate in-memory keyring with the ephemeral private key + certificate.
	keyring := sshagent.NewKeyring()
	comment := args.identity
	if comment == "" {
		comment = "ssh-vend-local ephemeral key"
	}
	if err := keyring.Add(sshagent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: args.ttlSecs,
	}); err != nil {
		if ownedDir {
			_ = os.RemoveAll(socketDir)
		}
		return nil, fmt.Errorf("add key to in-memory keyring: %w", err)
	}

	// Start the Unix-domain socket listener with restrictive permissions.
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if ownedDir {
			_ = os.RemoveAll(socketDir)
		}
		return nil, fmt.Errorf("listen on agent socket %s: %w", socketPath, err)
	}

	if args.debug {
		fmt.Fprintf(args.logw, "semaphore-agent: listening on %s\n", socketPath)
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	var serveWG sync.WaitGroup

	// Track active agent connections so closeRuntime can forcibly close them.
	var connMu sync.Mutex
	activeConns := make(map[net.Conn]struct{})

	// Accept loop: each inbound connection is served in its own goroutine.
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					// Normal shutdown; suppress the error.
				default:
					if args.debug {
						fmt.Fprintf(args.logw, "semaphore-agent: accept error: %v\n", err)
					}
				}
				return
			}

			connMu.Lock()
			activeConns[conn] = struct{}{}
			connMu.Unlock()

			serveWG.Add(1)
			go func(c net.Conn) {
				defer serveWG.Done()
				defer func() {
					connMu.Lock()
					delete(activeConns, c)
					connMu.Unlock()
					c.Close()
				}()
				if err := sshagent.ServeAgent(keyring, c); err != nil {
					if args.debug {
						fmt.Fprintf(args.logw, "semaphore-agent: agent conn error: %v\n", err)
					}
				}
			}(conn)
		}
	}()

	closeRuntime := func() error {
		var closeErr error
		closeOnce.Do(func() {
			close(done)

			// Stop accepting new connections.
			if err := listener.Close(); err != nil {
				closeErr = err
			}

			// Forcibly close all active agent connections so ServeAgent goroutines
			// can return promptly.
			connMu.Lock()
			for c := range activeConns {
				c.Close()
			}
			connMu.Unlock()

			serveWG.Wait() // wait for all goroutines before cleaning up files

			// Remove all identities from the keyring and drop references to private
			// key material as part of shutdown cleanup.
			_ = keyring.RemoveAll()

			if ownedDir {
				if err := os.RemoveAll(socketDir); err != nil && closeErr == nil {
					closeErr = err
				}
			} else {
				if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) && closeErr == nil {
					closeErr = err
				}
			}
		})
		return closeErr
	}

	return &EphemeralAgentRuntime{
		SocketPath: socketPath,
		Close:      closeRuntime,
	}, nil
}
