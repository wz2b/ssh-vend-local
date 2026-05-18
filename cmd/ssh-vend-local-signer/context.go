package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const expectedSignerUser = "ssh-vend-signer"

type signerExecutionContext struct {
	CallerUID  string
	CallerUser string
}

func checkSignerExecutionContext() (signerExecutionContext, error) {
	ctx := signerExecutionContext{
		CallerUID:  strings.TrimSpace(os.Getenv("SUDO_UID")),
		CallerUser: strings.TrimSpace(os.Getenv("SUDO_USER")),
	}

	if ctx.CallerUID == "" {
		return ctx, fmt.Errorf("SUDO_UID is required")
	}
	if ctx.CallerUser == "" {
		return ctx, fmt.Errorf("SUDO_USER is required")
	}

	effectiveUser, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return ctx, fmt.Errorf("lookup effective user: %w", err)
	}
	if effectiveUser.Username != expectedSignerUser {
		return ctx, fmt.Errorf("effective user must be %s, got %s", expectedSignerUser, effectiveUser.Username)
	}

	return ctx, nil
}
