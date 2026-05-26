package agentproto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Request struct {
	ID            string
	Method        string
	ContentLength int
	Body          []byte
}

type Response struct {
	ID      string
	Status  int
	Message string
	Body    []byte
}

func ParseHeaderKV(line string) (key, value string, err error) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("malformed header line: %q", line)
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), nil
}

func ReadRequest(r *bufio.Reader) (*Request, error) {
	startLine, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && startLine == "" {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read start line: %w", err)
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	if startLine != "AGENT/1 REQUEST" {
		return nil, fmt.Errorf("expected 'AGENT/1 REQUEST', got %q", startLine)
	}

	req := &Request{}
	hasContentLength := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, err := ParseHeaderKV(line)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key, "id"):
			req.ID = value
		case strings.EqualFold(key, "method"):
			req.Method = value
		case strings.EqualFold(key, "content-length"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Content-Length %q: %w", value, err)
			}
			if n < 0 {
				return nil, fmt.Errorf("Content-Length %d is negative", n)
			}
			req.ContentLength = n
			hasContentLength = true
		}
	}

	if !hasContentLength {
		return nil, fmt.Errorf("missing required Content-Length header in request")
	}
	if req.ContentLength > 0 {
		req.Body = make([]byte, req.ContentLength)
		if _, err := io.ReadFull(r, req.Body); err != nil {
			return nil, fmt.Errorf("read %d-byte request body: %w", req.ContentLength, err)
		}
	}
	return req, nil
}

func ReadResponse(r *bufio.Reader) (*Response, error) {
	startLine, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && startLine == "" {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read response start line: %w", err)
	}
	startLine = strings.TrimRight(startLine, "\r\n")
	if startLine != "AGENT/1 RESPONSE" {
		return nil, fmt.Errorf("expected 'AGENT/1 RESPONSE', got %q", startLine)
	}

	resp := &Response{}
	contentLength := 0
	hasContentLength := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read response header: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, err := ParseHeaderKV(line)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key, "id"):
			resp.ID = value
		case strings.EqualFold(key, "status"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Status %q: %w", value, err)
			}
			resp.Status = n
		case strings.EqualFold(key, "message"):
			resp.Message = value
		case strings.EqualFold(key, "content-length"):
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse Content-Length %q: %w", value, err)
			}
			if n < 0 {
				return nil, fmt.Errorf("Content-Length %d is negative", n)
			}
			contentLength = n
			hasContentLength = true
		}
	}

	if !hasContentLength {
		return nil, fmt.Errorf("missing required Content-Length header in response")
	}
	if contentLength > 0 {
		resp.Body = make([]byte, contentLength)
		if _, err := io.ReadFull(r, resp.Body); err != nil {
			return nil, fmt.Errorf("read %d-byte response body: %w", contentLength, err)
		}
	}
	return resp, nil
}

func WriteResponse(w io.Writer, resp Response) error {
	msg := resp.Message
	if msg == "" {
		if resp.Status == 200 {
			msg = "OK"
		} else {
			msg = "Error"
		}
	}

	header := fmt.Sprintf("AGENT/1 RESPONSE\nId: %s\nStatus: %d\nMessage: %s\nContent-Length: %d\n\n",
		resp.ID, resp.Status, msg, len(resp.Body))
	if _, err := io.WriteString(w, header); err != nil {
		return fmt.Errorf("write response header: %w", err)
	}
	if len(resp.Body) > 0 {
		if _, err := w.Write(resp.Body); err != nil {
			return fmt.Errorf("write response body: %w", err)
		}
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}
