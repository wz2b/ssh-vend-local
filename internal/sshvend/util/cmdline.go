package util

import (
	"io"

	"github.com/spf13/pflag"
	internalcmdline "github.com/wz2b/ssh-vend-local/internal/sshvend/cmdline"
	internalconfig "github.com/wz2b/ssh-vend-local/internal/sshvend/config"
)

func NewSubcommandFlagSet(name string, out io.Writer) *pflag.FlagSet {
	return internalcmdline.NewSubcommandFlagSet(name, out)
}

func ParseSubcommandArgs(fs *pflag.FlagSet, args []string, allowSingleDashLong bool) error {
	return internalcmdline.ParseSubcommandArgs(fs, args, allowSingleDashLong)
}

func LoadSubcommandConfig(fs *pflag.FlagSet) (internalconfig.Config, error) {
	return internalconfig.LoadConfig(fs)
}

func VisitedFlagNames(fs *pflag.FlagSet) map[string]bool {
	return internalcmdline.VisitedFlagNames(fs)
}

func RequireArg(name, value string) error {
	return internalcmdline.RequireArg(name, value)
}

func RequireArgCheck(name string, checker func() bool, message string) error {
	return internalcmdline.RequireArgCheck(name, checker, message)
}

func NormalizeSingleDashLongFlags(fs *pflag.FlagSet, args []string) []string {
	return internalcmdline.NormalizeSingleDashLongFlags(fs, args)
}
