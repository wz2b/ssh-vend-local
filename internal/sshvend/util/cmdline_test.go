package util

import (
	"strings"
	"testing"
)

func TestRequireArg(t *testing.T) {
	if err := RequireArg("principal", "ansible"); err != nil {
		t.Fatalf("RequireArg(valid) error: %v", err)
	}
	if err := RequireArg("principal", "   \t"); err == nil {
		t.Fatal("expected error for empty required arg")
	}
}

func TestRequireArgCheck(t *testing.T) {
	if err := RequireArgCheck("command", func() bool { return true }, ""); err != nil {
		t.Fatalf("RequireArgCheck(valid) error: %v", err)
	}
	if err := RequireArgCheck("command", func() bool { return false }, "must be provided"); err == nil {
		t.Fatal("expected error for failed arg check")
	} else if !strings.Contains(err.Error(), "must be provided") {
		t.Fatalf("expected custom message, got: %v", err)
	}
}

func TestNormalizeSingleDashLongFlags(t *testing.T) {
	fs := NewSubcommandFlagSet("test", nil)
	fs.String("profile", "", "")
	fs.String("ttl", "", "")

	args := []string{"-profile", "default", "--ttl", "15m", "-v", "--", "echo", "ok"}
	got := NormalizeSingleDashLongFlags(fs, args)

	want := []string{"--profile", "default", "--ttl", "15m", "-v", "--", "echo", "ok"}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d len(want)=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d]=%q want %q", i, got[i], want[i])
		}
	}
}
