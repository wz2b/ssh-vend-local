package agentruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/wz2b/ssh-vend-local/internal/sshvend/signerprocess"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type Runtime struct {
	SocketPath string
	Close      func() error
}

type RuntimeArgs struct {
	SignerCommand []string
	KeyType       string
	Profile       string
	Principal     string
	RequestedTTL  string
	Identity      string
	RuntimeDir    string
	TTLSeconds    uint32
	Verbose       bool
	Debug         bool
	Logw          io.Writer
}

// SignFunc is used by Build so tests can stub signer process execution.
var SignFunc = signerprocess.Sign

func Build(args RuntimeArgs) (*Runtime, error) {
	keyPair, err := genEphemeralKeypair(args.KeyType)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
	}

	certLine, err := SignFunc(signerprocess.Request{
		SignerCommand:       args.SignerCommand,
		PublicAuthorizedKey: keyPair.PubAuth,
		Profile:             args.Profile,
		RequestedTTL:        args.RequestedTTL,
		Identity:            args.Identity,
		Principal:           args.Principal,
		Verbose:             args.Verbose || args.Debug,
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

	socketDir := args.RuntimeDir
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
	if lstatInfo, lstatErr := os.Lstat(socketPath); lstatErr == nil {
		if lstatInfo.Mode()&os.ModeSocket != 0 {
			if err := os.Remove(socketPath); err != nil {
				if ownedDir {
					_ = os.RemoveAll(socketDir)
				}
				return nil, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
			}
		} else {
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

	keyring := sshagent.NewKeyring()
	comment := args.Identity
	if comment == "" {
		comment = "ssh-vend-local ephemeral key"
	}
	if err := keyring.Add(sshagent.AddedKey{
		PrivateKey:   privateKey,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: args.TTLSeconds,
	}); err != nil {
		if ownedDir {
			_ = os.RemoveAll(socketDir)
		}
		return nil, fmt.Errorf("add key to in-memory keyring: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if ownedDir {
			_ = os.RemoveAll(socketDir)
		}
		return nil, fmt.Errorf("listen on agent socket %s: %w", socketPath, err)
	}

	if args.Debug && args.Logw != nil {
		fmt.Fprintf(args.Logw, "semaphore-agent: listening on %s\n", socketPath)
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	var serveWG sync.WaitGroup
	var connMu sync.Mutex
	activeConns := make(map[net.Conn]struct{})

	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
				default:
					if args.Debug && args.Logw != nil {
						fmt.Fprintf(args.Logw, "semaphore-agent: accept error: %v\n", err)
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
				if err := sshagent.ServeAgent(keyring, c); err != nil && args.Debug && args.Logw != nil {
					fmt.Fprintf(args.Logw, "semaphore-agent: agent conn error: %v\n", err)
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
			connMu.Lock()
			for c := range activeConns {
				c.Close()
			}
			connMu.Unlock()
			serveWG.Wait()
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

	return &Runtime{SocketPath: socketPath, Close: closeRuntime}, nil
}

type ephemeralKeyPair struct {
	PrivPEM []byte
	PubAuth string
	Type    string
}

func genEphemeralKeypair(keyType string) (*ephemeralKeyPair, error) {
	switch keyType {
	case "ed25519", "":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return marshalEphemeralKey(priv, "ed25519")
	case "rsa":
		return nil, fmt.Errorf("rsa key type is not currently supported in agentruntime")
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func marshalEphemeralKey(privateKey any, keyType string) (*ephemeralKeyPair, error) {
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("create SSH signer: %w", err)
	}
	pubAuth := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	block, err := ssh.MarshalPrivateKey(privateKey, "ssh-vend-local ephemeral key")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("encode private key PEM: %w", err)
	}
	return &ephemeralKeyPair{PrivPEM: buf.Bytes(), PubAuth: pubAuth, Type: keyType}, nil
}

func parseCertificateLine(certLine string) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		return nil, fmt.Errorf("parse authorized key line: %w", err)
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("signed key is not an SSH certificate")
	}
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("expected user certificate, got cert type %d", cert.CertType)
	}
	return cert, nil
}
