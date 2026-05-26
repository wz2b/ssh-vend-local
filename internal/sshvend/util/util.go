package util

import (
	"crypto/rand"
	"log"
	"os"
)

func Must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func Verbosef(v bool, f string, a ...any) {
	if v {
		log.Printf(f, a...)
	}
}

func EnsureDir0600(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return nil
}

func RandSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const az = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range b {
		b[i] = az[int(b[i])%len(az)]
	}
	return string(b)
}

func RemoveIfExists(path string) {
	_ = os.Remove(path)
}

func CurrentExecutable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return p, nil
}
