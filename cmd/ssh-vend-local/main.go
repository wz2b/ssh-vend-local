package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "init-ca":
		initCA(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	case "print-server-config":
		printServerConfig(os.Args[2:])
	case "doctor":
		doctor(os.Args[2:])
	case "exec":
		if err := cmdExec(os.Args[2:]); err != nil {
			log.Fatal(err)
		}

	case "semaphore-agent":
		if err := cmdSemaphoreAgent(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ssh-vend-local

Local SSH certificate vending utility for development and testing.

Commands:
  init-ca              Generate a local OpenSSH user CA keypair
  sign                 Sign an SSH public key with the local CA
  exec                 Run a command with SSH agent environment for a signed cert
  print-server-config  Print sshd configuration instructions for trusting the CA
  doctor               Check required local tools

`)
}

func initCA(args []string) {
	fs := flag.NewFlagSet("init-ca", flag.ExitOnError)
	dir := fs.String("dir", "./local/ca", "directory where the local CA keypair will be created")
	_ = fs.Parse(args)

	fmt.Printf("TODO: initialize local CA in %s\n", *dir)
}

func sign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	caKey := fs.String("ca-key", "./local/ca/user_ca", "path to OpenSSH CA private key")
	publicKey := fs.String("public-key", "", "path to SSH public key to sign")
	principal := fs.String("principal", "semaphore-dev", "certificate principal")
	ttl := fs.String("ttl", "15m", "certificate lifetime")
	out := fs.String("out", "", "output certificate path")
	_ = fs.Parse(args)

	fmt.Printf("TODO: sign public key %s using CA %s principal=%s ttl=%s out=%s\n",
		*publicKey, *caKey, *principal, *ttl, *out)
}

func agent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	_ = fs.Parse(args)

	fmt.Println("TODO: run AGENT/1 external-agent protocol")
}

func printServerConfig(args []string) {
	fs := flag.NewFlagSet("print-server-config", flag.ExitOnError)
	caPub := fs.String("ca-pub", "./local/ca/user_ca.pub", "path to SSH CA public key")
	principal := fs.String("principal", "semaphore-dev", "certificate principal to allow")
	loginUser := fs.String("login-user", "ansible", "server-side Unix account that may accept the principal")
	_ = fs.Parse(args)

	fmt.Printf(`# Server-side OpenSSH certificate trust setup

# CA public key:
#   %s

# Target login user:
#   %s

# Allowed certificate principal:
#   %s

sudo mkdir -p /etc/ssh/ca
sudo install -m 0644 user_ca.pub /etc/ssh/ca/user_ca.pub

sudo mkdir -p /etc/ssh/auth_principals
echo %q | sudo tee /etc/ssh/auth_principals/%s

cat <<'SSHD_CONFIG' | sudo tee /etc/ssh/sshd_config.d/50-ssh-vend-local.conf
TrustedUserCAKeys /etc/ssh/ca/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u
SSHD_CONFIG

sudo sshd -t
sudo systemctl reload sshd || sudo systemctl reload ssh
`, *caPub, *loginUser, *principal, *principal, *loginUser)
}

func doctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	_ = fs.Parse(args)

	fmt.Println("TODO: check ssh-keygen, ssh-agent, ssh-add")
}
