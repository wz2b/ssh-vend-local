package semaphoreagent

import "testing"

func TestParseJSONConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		want    JSONConfig
		wantErr bool
	}{
		{"empty body", "", JSONConfig{}, false},
		{"whitespace only", "   \n  ", JSONConfig{}, false},
		{"empty object", "{}", JSONConfig{}, false},
		{"all fields", `{"profile":"p","principal":"u","ttl":"1h"}`,
			JSONConfig{Profile: "p", Principal: "u", TTL: "1h"}, false},
		{"partial fields", `{"principal":"ansible"}`,
			JSONConfig{Principal: "ansible"}, false},
		{"invalid json", "not-json", JSONConfig{}, true},
		{"ca_key rejected", `{"ca_key":"/tmp/key"}`, JSONConfig{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseJSONConfig([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
