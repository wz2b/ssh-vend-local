package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

func checkAccess(policyPath string, callerUID string, req SigningRequest, ttlSeconds int64) error {
	callerUID = strings.TrimSpace(callerUID)
	if callerUID == "" {
		return fmt.Errorf("caller UID is required")
	}

	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy file %s: %w", policyPath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(policyBytes))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	allowed := false
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			return fmt.Errorf("%s:%d: malformed policy line: expected uid:allowed_principals:allowed_signing_keys:max_ttl", policyPath, lineNo)
		}

		uid := strings.TrimSpace(parts[0])
		principals, err := parsePolicyCSV(parts[1])
		if err != nil {
			return fmt.Errorf("%s:%d: invalid allowed_principals: %w", policyPath, lineNo, err)
		}
		signingKeys, err := parsePolicyCSV(parts[2])
		if err != nil {
			return fmt.Errorf("%s:%d: invalid allowed_signing_keys: %w", policyPath, lineNo, err)
		}
		maxTTL, err := parseTTLSeconds(parts[3])
		if err != nil {
			return fmt.Errorf("%s:%d: invalid max_ttl: %w", policyPath, lineNo, err)
		}

		if uid == "" {
			return fmt.Errorf("%s:%d: uid is required", policyPath, lineNo)
		}

		if uid == callerUID && containsExact(principals, req.Principal) && containsExact(signingKeys, req.SigningKey) && ttlSeconds <= maxTTL {
			allowed = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan policy file %s: %w", policyPath, err)
	}

	if allowed {
		return nil
	}

	return fmt.Errorf("request denied by policy for caller_uid=%s principal=%q signing_key=%q requested_ttl=%ds", callerUID, req.Principal, req.SigningKey, ttlSeconds)
}

func parsePolicyCSV(field string) ([]string, error) {
	raw := strings.TrimSpace(field)
	if raw == "" {
		return nil, fmt.Errorf("field is empty")
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("field contains an empty value")
		}
		values = append(values, value)
	}

	return values, nil
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
