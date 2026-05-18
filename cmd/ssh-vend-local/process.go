package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// RunCommandWithAgent runs command with SSH_AUTH_SOCK set to socketPath.
//
// This is intentionally separate from cmdExec so cmdExec only has to deal with
// argument parsing, config loading, and high-level lifecycle:
//
//	start ephemeral agent
//	run command with agent
//	close ephemeral agent
func RunCommandWithAgent(command []string, socketPath string) error {
	if len(command) == 0 {
		return fmt.Errorf("missing command")
	}

	if socketPath == "" {
		return fmt.Errorf("missing SSH agent socket path")
	}

	child := exec.Command(command[0], command[1:]...)
	child.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socketPath)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigc)

	done := make(chan error, 1)

	go func() {
		done <- child.Wait()
	}()

	for {
		select {
		case sig := <-sigc:
			if child.Process != nil {
				_ = child.Process.Signal(sig)
			}

		case err := <-done:
			if err != nil {
				return fmt.Errorf("command failed: %w", err)
			}
			return nil
		}
	}
}
