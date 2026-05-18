package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	defaultProfilesFile = "/etc/ssh-vend-local/profiles"
	defaultKeysDir      = "/etc/ssh-vend-local/keys"
	defaultCertsDir     = "/etc/ssh-vend-local/certs"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("ssh-vend-local-signer: ")

	fs := flag.NewFlagSet("ssh-vend-local-signer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	debug := fs.Bool("debug", false, "enable debug logging")
	fs.Usage = usage

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}

	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n\n", fs.Args())
		usage()
		os.Exit(2)
	}

	if err := runSigner(os.Stdin, os.Stdout, *debug); err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ssh-vend-local-signer [--debug]

Privileged stdin/stdout SSH certificate signer.

Input JSON on stdin:
  {
    "public_key": "ssh-ed25519 AAAA...",
    "principal": "ansadmin",
    "signing_key": "default",
    "requested_ttl": "15m",
    "identity": "semaphore-task-123"
  }

Policy file:
  %s

Signing keys:
  %s/<name>
  %s/<name>.pub

Certificates directory:
  %s/

Output:
  One OpenSSH user certificate authorized-key line on stdout.
  Diagnostics and debug output go to stderr.

Policy format:
  uid:allowed_principals:allowed_signing_keys:max_ttl

Example:
  1000:ansadmin,deploy:default,lab:3600
  995:ansadmin:default:900

`, defaultProfilesFile, defaultKeysDir, defaultKeysDir, defaultCertsDir)
}

func runSigner(stdin io.Reader, stdout io.Writer, debug bool) error {
	requestBytes, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read signing request: %w", err)
	}

	req, ttlSeconds, err := parseSigningRequest(requestBytes)
	if err != nil {
		return err
	}

	if debug {
		log.Printf("request principal=%q signing_key=%q requested_ttl=%ds identity=%q", req.Principal, req.SigningKey, ttlSeconds, req.Identity)
	}

	ctx, err := checkSignerExecutionContext()
	if err != nil {
		return err
	}

	if debug {
		log.Printf("execution context caller_uid=%q caller_user=%q", ctx.CallerUID, ctx.CallerUser)
	}

	signingKeyPath, err := resolveSigningKeyPath(req.SigningKey)
	if err != nil {
		return err
	}

	if err := checkAccess(defaultProfilesFile, ctx.CallerUID, req, ttlSeconds); err != nil {
		return err
	}

	certLine, err := signCertificate(req, signingKeyPath, ttlSeconds)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(stdout, certLine); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}
