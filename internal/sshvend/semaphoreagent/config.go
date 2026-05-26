package semaphoreagent

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JSONConfig holds optional fields from the AGENT/1 Semaphore config body.
type JSONConfig struct {
	Profile   string `json:"profile"`
	Principal string `json:"principal"`
	TTL       string `json:"ttl"`
}

// ParseJSONConfig parses an optional Semaphore external-agent config JSON body.
// Empty/whitespace and {} are accepted and return a zero-value config.
// The ca_key field is explicitly rejected.
func ParseJSONConfig(body []byte) (JSONConfig, error) {
	var cfg JSONConfig
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return cfg, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return cfg, fmt.Errorf("parse JSON config body: %w", err)
	}
	if _, ok := fields["ca_key"]; ok {
		return cfg, fmt.Errorf("config field %q is not supported; CA selection is profile-based", "ca_key")
	}

	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		return cfg, fmt.Errorf("parse JSON config body: %w", err)
	}
	return cfg, nil
}
