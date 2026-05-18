
import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	signerUserName   = "ssh-vend-signer"
	callersGroupName = "ssh-vend-callers"

	baseDirPath    = "/etc/ssh-vend-local"
	keysDirPath    = "/etc/ssh-vend-local/keys"
	certsDirPath   = "/etc/ssh-vend-local/certs"
	profilesPath   = "/etc/ssh-vend-local/profiles"
	sudoersPath    = "/etc/sudoers.d/ssh-vend-local"
	defaultKeyPath = "/etc/ssh-vend-local/keys/default"
	defaultPubPath = "/etc/ssh-vend-local/certs/default.pub"
)

func initSigner() error {
	if err := requireRoot(); err != nil {
		return err
	}

	fmt.Println("Initializing local ssh-vend-local signer environment...")

	if err := ensureGroup(signerUserName); err != nil {
		return err
	}
	if err := ensureGroup(callersGroupName); err != nil {
		return err
	}
	if err := ensureUser(signerUserName); err != nil {
		return err
	}

	if err := ensureDir(baseDirPath, "root", "root", 0o755); err != nil {
		return err
	}
	if err := ensureDir(certsDirPath, "root", "root", 0o755); err != nil {
		return err
	}
	if err := ensureDir(keysDirPath, "root", signerUserName, 0o750); err != nil {
		return err
	}

	if err := ensureSudoersFile(); err != nil {
		return err
	}
	if err := ensureProfilesFile(); err != nil {
		return err
	}

	created, err := ensureDefaultKeypair()
	if err != nil {
		return err
	}
	if created {
		fmt.Println("Created a new default SSH CA signing keypair.")
		fmt.Println("Private key: /etc/ssh-vend-local/keys/default")
		fmt.Println("Public key:  /etc/ssh-vend-local/certs/default.pub")
	} else {
		fmt.Println("Default signing key already exists; leaving existing key material unchanged.")
	}

	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Println("  1. Add users that may request certificates to the ssh-vend-callers group:")
	fmt.Println("       sudo usermod -aG ssh-vend-callers <username>")
	fmt.Println("")
	fmt.Println("  2. Edit /etc/ssh-vend-local/profiles and add policy lines.")
	fmt.Println("     Example:")
	fmt.Println("       <uid>:ansadmin:default:3600")
	fmt.Println("")
	fmt.Println("  3. Install /etc/ssh-vend-local/certs/default.pub on target SSH servers using TrustedUserCAKeys.")
	fmt.Println("")
	fmt.Println("  4. Make sure /usr/local/bin/ssh-vend-local-signer exists and is executable.")

	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("init-signer must run as root")
	}
	return nil
}

func ensureGroup(name string) error {
	exists, err := commandSucceeds("getent", "group", name)
	if err != nil {
		return err
	}
	if exists {
		fmt.Printf("Group %q already exists; leaving unchanged.\n", name)
		return nil
	}

	if _, err := runCommand("groupadd", "--system", name); err != nil {
		return err
	}
	fmt.Printf("Created system group %q.\n", name)
	return nil
}

func ensureUser(name string) error {
	exists, err := commandSucceeds("id", "-u", name)
	if err != nil {
		return err
	}
	if exists {
		fmt.Printf("User %q already exists; leaving unchanged.\n", name)
		return nil
	}

	if _, err := runCommand("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name); err != nil {
		return err
	}
	fmt.Printf("Created system user %q.\n", name)
	return nil
}

func ensureDir(path string, owner string, group string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}

	uid, gid, err := lookupUserGroupIDs(owner, group)
	if err != nil {
		return fmt.Errorf("resolve owner/group for %s: %w", path, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s:%s: %w", path, owner, group, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s to %04o: %w", path, mode, err)
	}

	fmt.Printf("Ensured directory %s (%s:%s %04o).\n", path, owner, group, mode)
	return nil
}

func ensureSudoersFile() error {
	if _, err := os.Stat(sudoersPath); err == nil {
		fmt.Printf("Sudoers file %s already exists; leaving unchanged.\n", sudoersPath)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", sudoersPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(sudoersPath), 0o755); err != nil {
		return fmt.Errorf("create sudoers directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(sudoersPath), "ssh-vend-local-sudoers-*")
	if err != nil {
		return fmt.Errorf("create temporary sudoers file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	content := "# Allow selected users to invoke the SSH certificate signer.\n" +
		"#\n" +
		"# The signer runs as ssh-vend-signer, which can read the private CA signing keys\n" +
		"# under /etc/ssh-vend-local/keys.\n" +
		"#\n" +
		"# The invoking user does not receive direct read access to the signing keys.\n" +
		"#\n" +
		"# ssh-vend-local-signer uses SUDO_UID as the original caller identity, but only\n" +
		"# trusts it when the effective user is ssh-vend-signer. Policy is then checked\n" +
		"# against SUDO_UID.\n\n" +
		"Cmnd_Alias SSH_VEND_LOCAL_SIGNER = /usr/local/bin/ssh-vend-local-signer\n\n" +
		"%ssh-vend-callers ALL=(ssh-vend-signer:ssh-vend-signer) NOPASSWD: SSH_VEND_LOCAL_SIGNER\n"

	if _, err := io.WriteString(tmpFile, content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temporary sudoers file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temporary sudoers file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o440); err != nil {
		return fmt.Errorf("chmod temporary sudoers file: %w", err)
	}

	if _, err := runCommand("visudo", "-cf", tmpPath); err != nil {
		return fmt.Errorf("validate sudoers file: %w", err)
	}

	if err := os.Rename(tmpPath, sudoersPath); err != nil {
		return fmt.Errorf("install sudoers file: %w", err)
	}
	cleanupTmp = false

	uid, gid, err := lookupUserGroupIDs("root", "root")
	if err != nil {
		return fmt.Errorf("resolve root owner/group: %w", err)
	}
	if err := os.Chown(sudoersPath, uid, gid); err != nil {
		return fmt.Errorf("chown sudoers file: %w", err)
	}
	if err := os.Chmod(sudoersPath, 0o440); err != nil {
		return fmt.Errorf("chmod sudoers file: %w", err)
	}

	fmt.Printf("Created sudoers file %s.\n", sudoersPath)
	return nil
}

func ensureProfilesFile() error {
	f, err := os.OpenFile(profilesPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Printf("Profiles file %s already exists; leaving unchanged.\n", profilesPath)
			return nil
		}
		return fmt.Errorf("create profiles file %s: %w", profilesPath, err)
	}

	content := "# ssh-vend-local signer policy\n" +
		"#\n" +
		"# Format:\n" +
		"#   uid:allowed_principals:allowed_signing_keys:max_ttl\n" +
		"#\n" +
		"# Example:\n" +
		"#   1000:ansadmin,deploy:default:3600\n" +
		"#\n" +
		"# Notes:\n" +
		"#   - uid is the original caller UID from SUDO_UID\n" +
		"#   - allowed_principals is a comma-separated list\n" +
		"#   - allowed_signing_keys is a comma-separated list of key names\n" +
		"#   - max_ttl is the maximum certificate lifetime in seconds\n"

	if _, err := io.WriteString(f, content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write profiles file %s: %w", profilesPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close profiles file %s: %w", profilesPath, err)
	}

	uid, gid, err := lookupUserGroupIDs("root", signerUserName)
	if err != nil {
		return fmt.Errorf("resolve owner/group for profiles file: %w", err)
	}
	if err := os.Chown(profilesPath, uid, gid); err != nil {
		return fmt.Errorf("chown profiles file %s: %w", profilesPath, err)
	}
	if err := os.Chmod(profilesPath, 0o640); err != nil {
		return fmt.Errorf("chmod profiles file %s: %w", profilesPath, err)
	}

	fmt.Printf("Created profiles file %s.\n", profilesPath)
	return nil
}

func ensureDefaultKeypair() (bool, error) {
	privateExists, err := pathExists(defaultKeyPath)
	if err != nil {
		return false, err
	}
	publicExists, err := pathExists(defaultPubPath)
	if err != nil {
		return false, err
	}
	if privateExists || publicExists {
		return false, nil
	}

	tmpDir, err := os.MkdirTemp("", "ssh-vend-local-keypair-*")
	if err != nil {
		return false, fmt.Errorf("create temporary directory for key generation: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpKeyBase := filepath.Join(tmpDir, "default")
	if _, err := runCommand("ssh-keygen", "-t", "ed25519", "-f", tmpKeyBase, "-N", "", "-C", "ssh-vend-local default user CA"); err != nil {
		return false, err
	}

	privateBytes, err := os.ReadFile(tmpKeyBase)
	if err != nil {
		return false, fmt.Errorf("read generated private key: %w", err)
	}
	publicBytes, err := os.ReadFile(tmpKeyBase + ".pub")
	if err != nil {
		return false, fmt.Errorf("read generated public key: %w", err)
	}

	if err := os.WriteFile(defaultKeyPath, privateBytes, 0o600); err != nil {
		return false, fmt.Errorf("install private key %s: %w", defaultKeyPath, err)
	}
	if err := os.WriteFile(defaultPubPath, publicBytes, 0o644); err != nil {
		return false, fmt.Errorf("install public key %s: %w", defaultPubPath, err)
	}

	signerUID, signerGID, err := lookupUserGroupIDs(signerUserName, signerUserName)
	if err != nil {
		return false, fmt.Errorf("resolve signer user/group: %w", err)
	}
	rootUID, rootGID, err := lookupUserGroupIDs("root", "root")
	if err != nil {
		return false, fmt.Errorf("resolve root user/group: %w", err)
	}

	if err := os.Chown(defaultKeyPath, signerUID, signerGID); err != nil {
		return false, fmt.Errorf("chown private key %s: %w", defaultKeyPath, err)
	}
	if err := os.Chmod(defaultKeyPath, 0o600); err != nil {
		return false, fmt.Errorf("chmod private key %s: %w", defaultKeyPath, err)
	}
	if err := os.Chown(defaultPubPath, rootUID, rootGID); err != nil {
		return false, fmt.Errorf("chown public key %s: %w", defaultPubPath, err)
	}
	if err := os.Chmod(defaultPubPath, 0o644); err != nil {
		return false, fmt.Errorf("chmod public key %s: %w", defaultPubPath, err)
	}

	return true, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}

func commandSucceeds(name string, args ...string) (bool, error) {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, fmt.Errorf("run command %q: %w", commandLine(name, args...), err)
	}
	return true, nil
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return "", fmt.Errorf("command %q failed: %w: %s", commandLine(name, args...), err, string(output))
		}
		return "", fmt.Errorf("command %q failed: %w", commandLine(name, args...), err)
	}
	return string(output), nil
}

func lookupUserGroupIDs(owner, group string) (int, int, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", owner, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %q: %w", group, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q for user %q: %w", u.Uid, owner, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q for group %q: %w", g.Gid, group, err)
	}

	return uid, gid, nil
}

func commandLine(name string, args ...string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
