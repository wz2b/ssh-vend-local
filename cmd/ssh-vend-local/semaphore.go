package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wz2b/ssh-vend-local/internal/sshvend/agentproto"
	"github.com/wz2b/ssh-vend-local/internal/sshvend/agentruntime"
	"github.com/wz2b/ssh-vend-local/internal/sshvend/semaphoreagent"
	sshutil "github.com/wz2b/ssh-vend-local/internal/sshvend/util"
)

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
	fs := sshutil.NewSubcommandFlagSet("semaphore-agent", logw)
	registerCommonFlags(fs)
	debugFlag := fs.Bool("debug", false, "Enable debug log output")

	if err := sshutil.ParseSubcommandArgs(fs, args, true); err != nil {
		return err
	}

	// Record which flags were explicitly supplied by the caller.
	// Used to implement CLI flag > JSON config > default precedence.
	visited := sshutil.VisitedFlagNames(fs)

	logf := func(format string, a ...any) {
		if *debugFlag {
			fmt.Fprintf(logw, "semaphore-agent: "+format+"\n", a...)
		}
	}

	// stdout is reserved for AGENT/1 framed responses only.
	bw := bufio.NewWriter(stdout)
	in := bufio.NewReader(stdin)

	// ── Step 1: read config request ────────────────────────────────────────
	configReq, err := agentproto.ReadRequest(in)
	if err != nil {
		return fmt.Errorf("read config request: %w", err)
	}
	if configReq.Method != "config" {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte(fmt.Sprintf("expected Method: config, got %q", configReq.Method)),
		})
		return fmt.Errorf("expected Method: config, got %q", configReq.Method)
	}
	logf("received config request (body %d bytes)", len(configReq.Body))

	cfg, err := sshutil.LoadSubcommandConfig(fs)
	if err != nil {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
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
	jsonCfg, err := semaphoreagent.ParseJSONConfig(configReq.Body)
	if err != nil {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
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
	if err := sshutil.RequireArg("principal", effectivePrincipal); err != nil {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
			ID:      configReq.ID,
			Status:  400,
			Message: "Bad Request",
			Body:    []byte("principal is required (use -principal flag or JSON config field)"),
		})
		return err
	}
	principalStr := strings.TrimSpace(effectivePrincipal)

	ttlSecs, err := sshutil.LifetimeSeconds(effectiveTTL)
	if err != nil {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
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
	runtime, err := agentruntime.Build(agentruntime.RuntimeArgs{
		SignerCommand: cfg.SignerCommand,
		KeyType:       cfg.KeyType,
		Profile:       effectiveProfile,
		Principal:     principalStr,
		RequestedTTL:  effectiveTTL,
		Identity:      identity,
		RuntimeDir:    cfg.RuntimeDir,
		TTLSeconds:    ttlSecs,
		Verbose:       cfg.Verbose,
		Debug:         *debugFlag,
		Logw:          logw,
	})
	if err != nil {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
			ID:      configReq.ID,
			Status:  500,
			Message: "Internal Error",
			Body:    []byte(err.Error()),
		})
		return fmt.Errorf("build agent runtime: %w", err)
	}
	logf("agent socket ready: %s", runtime.SocketPath)

	// ── Step 5: send 200 OK with socket path ───────────────────────────────
	if err := agentproto.WriteResponse(bw, agentproto.Response{
		ID:     configReq.ID,
		Status: 200,
		Body:   []byte(runtime.SocketPath),
	}); err != nil {
		_ = runtime.Close()
		return fmt.Errorf("write config response: %w", err)
	}

	// ── Step 6: wait for shutdown request ─────────────────────────────────
	logf("waiting for shutdown request")
	shutdownReq, err := agentproto.ReadRequest(in)
	if err != nil {
		_ = runtime.Close()
		if errors.Is(err, io.EOF) {
			logf("stdin closed; shutting down without explicit shutdown request")
			return nil
		}
		return fmt.Errorf("read shutdown request: %w", err)
	}
	if shutdownReq.Method != "shutdown" {
		_ = agentproto.WriteResponse(bw, agentproto.Response{
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

	if err := agentproto.WriteResponse(bw, agentproto.Response{
		ID:     shutdownReq.ID,
		Status: 200,
	}); err != nil {
		return fmt.Errorf("write shutdown response: %w", err)
	}

	logf("shutdown complete")
	return nil
}
