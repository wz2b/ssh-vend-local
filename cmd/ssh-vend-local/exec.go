package main

import (
	"flag"
	"fmt"

	"github.com/spf13/pflag"
	"github.com/wz2b/ssh-vend-local/internal/sshvend/agentruntime"
	sshutil "github.com/wz2b/ssh-vend-local/internal/sshvend/util"
)

func cmdExec(args []string) error {
	before, command := splitCommand(args)

	fs := sshutil.NewSubcommandFlagSet("exec", nil)
	registerCommonFlags(fs)

	if err := sshutil.ParseSubcommandArgs(fs, before, false); err != nil {
		return err
	}

	if err := sshutil.RequireArgCheck("command", func() bool {
		return len(command) > 0
	}, "command to execute is required (use: exec [flags] -- COMMAND ...)"); err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	cfg, err := sshutil.LoadSubcommandConfig(fs)
	if err != nil {
		return err
	}

	principal, _ := fs.GetString("principal")
	if err := sshutil.RequireArg("principal", principal); err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	lifetimeSecs, err := sshutil.LifetimeSeconds(cfg.TTL)
	if err != nil {
		return err
	}

	runtime, err := agentruntime.Build(agentruntime.RuntimeArgs{
		SignerCommand: cfg.SignerCommand,
		KeyType:       cfg.KeyType,
		Profile:       cfg.Profile,
		Principal:     principal,
		RequestedTTL:  cfg.TTL,
		Identity:      cfg.Identity,
		TTLSeconds:    lifetimeSecs,
		Verbose:       cfg.Verbose,
	})
	if err != nil {
		return fmt.Errorf("start ephemeral SSH agent: %w", err)
	}
	defer runtime.Close()

	return sshutil.RunCommandWithAgent(command, runtime.SocketPath)
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
