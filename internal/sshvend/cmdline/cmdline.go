package cmdline

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
)

func NewSubcommandFlagSet(name string, out io.Writer) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	if out != nil {
		fs.SetOutput(out)
	}
	return fs
}

func ParseSubcommandArgs(fs *pflag.FlagSet, args []string, allowSingleDashLong bool) error {
	if allowSingleDashLong {
		args = NormalizeSingleDashLongFlags(fs, args)
	}
	return fs.Parse(args)
}

func VisitedFlagNames(fs *pflag.FlagSet) map[string]bool {
	visited := make(map[string]bool)
	fs.Visit(func(f *pflag.Flag) { visited[f.Name] = true })
	return visited
}

func RequireArg(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func RequireArgCheck(name string, checker func() bool, message string) error {
	if checker == nil || !checker() {
		if strings.TrimSpace(message) == "" {
			return fmt.Errorf("invalid %s", name)
		}
		return fmt.Errorf("%s: %s", name, message)
	}
	return nil
}

func NormalizeSingleDashLongFlags(fs *pflag.FlagSet, args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") || len(arg) <= 2 {
			out = append(out, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "-")
		if strings.Contains(name, "=") {
			name = strings.SplitN(name, "=", 2)[0]
		}
		if fs != nil && fs.Lookup(name) != nil {
			out = append(out, "--"+strings.TrimPrefix(arg, "-"))
			continue
		}
		out = append(out, arg)
	}
	return out
}
