package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type EphemeralAgentKey struct {
	PrivateKey       any
	Certificate      *ssh.Certificate
	Comment          string
	LifetimeSecs     uint32
	ConfirmBeforeUse bool
}

type EphemeralAgentRuntime struct {
	SocketPath string
	Close      func() error
}

// StartEphemeralAgent starts an in-process SSH agent compatible with SSH_AUTH_SOCK.
//
// This function does not generate keys, sign certificates, read policy, read CA
// material, or start OpenSSH ssh-agent. It only exposes the supplied certified
// key through the SSH agent protocol.
//
// Key and certificate material remain in memory. The only filesystem object is
// the Unix-domain socket path required by SSH_AUTH_SOCK.
func StartEphemeralAgent(key EphemeralAgentKey, verbose bool) (*EphemeralAgentRuntime, error) {
	if key.PrivateKey == nil {
		return nil, errors.New("missing private key")
	}
	if key.Certificate == nil {
		return nil, errors.New("missing certificate")
	}

	socketDir, err := os.MkdirTemp("", "ssh-vend-local-agent-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary socket directory: %w", err)
	}

	socketPath := filepath.Join(socketDir, "agent.sock")

	keyring := sshagent.NewKeyring()

	comment := key.Comment
	if comment == "" {
		comment = "ssh-vend-local ephemeral key"
	}

	runtime, err2 := AddKey(key, keyring, comment, socketDir)
	if err2 != nil {
		return runtime, err2
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("listen on agent socket: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "ssh-vend-local: in-process SSH agent socket: %s\n", socketPath)
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	var serveWG sync.WaitGroup

	serveWG.Add(1)
	go func() {
		defer serveWG.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					if verbose {
						fmt.Fprintf(os.Stderr, "ssh-vend-local: agent accept error: %v\n", err)
					}
					return
				}
			}

			serveWG.Add(1)
			go func(conn net.Conn) {
				defer serveWG.Done()
				defer conn.Close()

				if err := sshagent.ServeAgent(keyring, conn); err != nil && verbose {
					fmt.Fprintf(os.Stderr, "ssh-vend-local: agent connection error: %v\n", err)
				}
			}(conn)
		}
	}()

	closeRuntime := func() error {
		var closeErr error

		closeOnce.Do(func() {
			close(done)

			if err := listener.Close(); err != nil {
				closeErr = err
			}

			serveWG.Wait()

			if err := os.RemoveAll(socketDir); err != nil && closeErr == nil {
				closeErr = err
			}
		})

		return closeErr
	}

	return &EphemeralAgentRuntime{
		SocketPath: socketPath,
		Close:      closeRuntime,
	}, nil
}

func AddKey(key EphemeralAgentKey, keyring sshagent.Agent, comment string, socketDir string) (*EphemeralAgentRuntime, error) {
	if err := keyring.Add(sshagent.AddedKey{
		PrivateKey:       key.PrivateKey,
		Certificate:      key.Certificate,
		Comment:          comment,
		LifetimeSecs:     key.LifetimeSecs,
		ConfirmBeforeUse: key.ConfirmBeforeUse,
	}); err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("add key to in-memory agent: %w", err)
	}
	return nil, nil
}
