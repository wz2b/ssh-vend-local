package main

import (
	"crypto/rand"
	"log"
	"os"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func verbosef(v bool, f string, a ...any) {
	if v {
		log.Printf(f, a...)
	}
}

func ensureDir0600(path string) error {
	// 0700 is typical for runtime dirs
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return nil
}

func randSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const az = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range b {
		b[i] = az[int(b[i])%len(az)]
	}
	return string(b)
}

func removeIfExists(path string) {
	_ = os.Remove(path)
}

func currentExecutable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return p, nil
}

//func resolveRuntimeDir(cfg *Config) (string, error) {
//	uid := os.Geteuid()
//
//	// 0) If config specifies a dir and it's sane, use it.
//	if d := strings.TrimSpace(cfg.RuntimeDir); d != "" {
//		if dirLooksUsableForUID(d, uid) {
//			if err := os.MkdirAll(d, 0o700); err == nil {
//				return d, nil
//			}
//		}
//		// else: warn and fall through to auto-default
//		verbosef(cfg.Debug, "ignoring cfg.RuntimeDir=%q (not writable or wrong uid); using auto-default", d)
//	}
//
//	// 1) XDG_RUNTIME_DIR (works on many Linux/Unix distros, sometimes macOS)
//	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" && dirLooksUsableForUID(base, uid) {
//		d := filepath.Join(base, "rit-ssh-agent-"+strconv.Itoa(uid))
//		if err := os.MkdirAll(d, 0o700); err == nil {
//			return d, nil
//		}
//	}
//
//	// 2) Linux systemd user runtime
//	if runtime.GOOS == "linux" {
//		base := fmt.Sprintf("/run/user/%d", uid)
//		if st, err := os.Stat(base); err == nil && st.IsDir() && dirLooksUsableForUID(base, uid) {
//			d := filepath.Join(base, "rit-ssh-agent-"+strconv.Itoa(uid))
//			if err := os.MkdirAll(d, 0o700); err == nil {
//				return d, nil
//			}
//		}
//	}
//
//	// 3) Portable fallback: per-uid dir under the OS temp dir
//	base := os.TempDir() // macOS -> /var/folders/.../T, Linux -> /tmp, Windows -> %TEMP%
//	d := filepath.Join(base, "rit-ssh-agent-"+strconv.Itoa(uid))
//	if err := os.MkdirAll(d, 0o700); err != nil {
//		return "", fmt.Errorf("mkdir %s: %w", d, err)
//	}
//	return d, nil
//}

//func dirLooksUsableForUID(path string, uid int) bool {
//	// Best-effort: writable and (on Unix) owned by this uid or world-inaccessible
//	if err := os.MkdirAll(path, 0o700); err != nil {
//		return false
//	}
//	// On Unix, check ownership. On Windows, skip.
//	if runtime.GOOS != "windows" {
//		if st, err := os.Stat(path); err == nil {
//			if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != uid {
//				return false
//			}
//		}
//	}
//	// Check writability by trying to create then remove a file.
//	test := filepath.Join(path, ".wtest")
//	if f, err := os.Create(test); err != nil {
//		return false
//	} else {
//		_ = f.Close()
//		_ = os.Remove(test)
//	}
//	return true
//}
//
//func socketPath(cfg *Config) (string, error) {
//	dir, err := resolveRuntimeDir(cfg)
//	if err != nil {
//		return "", err
//	}
//	name := cfg.SocketName
//	if name == "" {
//		name = "rit-ssh-agent.sock"
//	}
//	return filepath.Join(dir, name), nil
//}
