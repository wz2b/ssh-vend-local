package agentproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReadRequest_Config(t *testing.T) {
	body := []byte("hello")
	raw := fmt.Sprintf("AGENT/1 REQUEST\nId: 1\nMethod: config\nContent-Length: %d\n\n%s", len(body), body)

	req, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.ID != "1" || req.Method != "config" || string(req.Body) != string(body) {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestReadRequest_MissingContentLength(t *testing.T) {
	_, err := ReadRequest(bufio.NewReader(strings.NewReader("AGENT/1 REQUEST\nId: 1\nMethod: config\n\n")))
	if err == nil {
		t.Fatal("expected missing Content-Length error")
	}
}

func TestReadResponse_MissingContentLength(t *testing.T) {
	_, err := ReadResponse(bufio.NewReader(strings.NewReader("AGENT/1 RESPONSE\nId: 1\nStatus: 200\nMessage: OK\n\n")))
	if err == nil {
		t.Fatal("expected missing Content-Length error")
	}
}

func TestWriteResponse_ContentLength(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("sock")
	if err := WriteResponse(&buf, Response{ID: "1", Status: 200, Body: body}); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Content-Length: 4") {
		t.Fatalf("missing content-length header: %q", out)
	}
	if !strings.HasSuffix(out, string(body)) {
		t.Fatalf("response body mismatch: %q", out)
	}
}

func TestReadResponse_EOF(t *testing.T) {
	_, err := ReadResponse(bufio.NewReader(strings.NewReader("")))
	if err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
}
