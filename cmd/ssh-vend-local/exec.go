package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

func cmdExec(args []string) error {
	before, command := splitCommand(args)

	fs := pflag.NewFlagSet("exec", pflag.ContinueOnError)
	registerCommonFlags(fs)

	if err := fs.Parse(before); err != nil {
		return err
	}

	if len(command) == 0 {
		return errors.New("exec: missing COMMAND (use: exec [flags] -- COMMAND ...)")
	}

	cfg, err := LoadConfig(fs)
	if err != nil {
		return err
	}

	keyPair, err := genEphemeralKeypair(cfg.KeyType)
	if err != nil {
		return fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	principal, _ := fs.GetString("principal")

	certLine, err := SignEphemeralKey(SignEphemeralKeyRequest{
		SignerCommand:       cfg.SignerCommand,
		PublicAuthorizedKey: keyPair.PubAuth,
		Principal:           principal,
		Profile:             cfg.Profile,
		RequestedTTL:        cfg.TTL,
		Identity:            cfg.Identity,
		Verbose:             cfg.Verbose,
	})
	if err != nil {
		return fmt.Errorf("sign ephemeral key: %w", err)
	}

	cert, err := parseCertificateLine(certLine)
	if err != nil {
		return fmt.Errorf("parse signed certificate: %w", err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(keyPair.PrivPEM)
	if err != nil {
		return fmt.Errorf("parse ephemeral private key: %w", err)
	}

	lifetimeSecs, err := lifetimeSeconds(cfg.TTL)
	if err != nil {
		return err
	}

	runtime, err := StartEphemeralAgent(EphemeralAgentKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		Comment:      cfg.Identity,
		LifetimeSecs: lifetimeSecs,
	}, cfg.Verbose)
	if err != nil {
		return fmt.Errorf("start ephemeral SSH agent: %w", err)
	}
	defer runtime.Close()

	return RunCommandWithAgent(command, runtime.SocketPath)
}

func registerCommonFlags(fs *pflag.FlagSet) {
	fs.BoolP("verbose", "v", false, "Verbose logging")
	fs.String("key-type", "", "Ephemeral key type: ed25519 or rsa. Default is ed25519")
	fs.String("profile", "", "Signer profile to request. Default is default")
	fs.String("ttl", "", "Requested certificate lifetime. Default is 15m")
	fs.String("identity", "", "Requested certificate identity / key ID")
	fs.String("principal", "", "Requested SSH certificate principal. Default is current OS user")
	fs.StringArray("signer-command", nil, "External signer command. Repeat for each argv element.")
	fs.String("runtime-dir", "", "Runtime directory. Default is temporary")
}

func splitCommand(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}

	return args, nil
}

// Keep stdlib flag usage text quiet when pflag parses fail.
func init() {
	flag.CommandLine = flag.NewFlagSet("ssh-vend-local", flag.ContinueOnError)
}
