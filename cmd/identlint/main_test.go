package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Brave 151, as captured. Nothing in it is wrong, so it is the clean case.
const clean = `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
sec-ch-ua: "Not=A?Brand";v="99", "Brave";v="151", "Chromium";v="151"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
accept-encoding: gzip, deflate, br, zstd
`

// The same with the User-Agent bumped to 152 and nothing else, which is
// what a hand-edited client tends to look like.
const bumped = `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
sec-ch-ua: "Not=A?Brand";v="99", "Brave";v="151", "Chromium";v="151"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
accept-encoding: gzip, deflate, br, zstd
`

const har = `{"log":{"entries":[
 {"request":{"url":"https://example.test/?SECRET","headers":[
   {"name":"user-agent","value":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"},
   {"name":"sec-ch-ua","value":"\"Not=A?Brand\";v=\"99\", \"Brave\";v=\"151\", \"Chromium\";v=\"151\""},
   {"name":"sec-ch-ua-mobile","value":"?0"},
   {"name":"sec-ch-ua-platform","value":"\"Windows\""},
   {"name":"sec-fetch-mode","value":"navigate"},
   {"name":"cookie","value":"SECRET"}]}},
 {"request":{"url":"https://example.test/?SECRET","headers":[
   {"name":"user-agent","value":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"},
   {"name":"sec-ch-ua","value":"\"Not=A?Brand\";v=\"99\", \"Brave\";v=\"151\", \"Chromium\";v=\"151\""},
   {"name":"sec-ch-ua-mobile","value":"?0"},
   {"name":"sec-ch-ua-platform","value":"\"Windows\""},
   {"name":"sec-fetch-mode","value":"navigate"},
   {"name":"referer","value":"https://example.test/?SECRET"}]}},
 {"request":{"url":"https://example.test/?SECRET","headers":[
   {"name":"user-agent","value":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"},
   {"name":"sec-ch-ua-mobile","value":"?0"},
   {"name":"sec-ch-ua-platform","value":"\"Windows\""},
   {"name":"sec-ch-ua","value":"\"Not=A?Brand\";v=\"99\", \"Brave\";v=\"151\", \"Chromium\";v=\"151\""},
   {"name":"sec-fetch-mode","value":"navigate"}]}}
]}}`

func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	cleanFile := write(t, dir, "clean.txt", clean)
	bumpedFile := write(t, dir, "bumped.txt", bumped)
	harFile := write(t, dir, "capture.har", har)
	// Brave 151 sends user-agent before sec-ch-ua, so this is the other way.
	orderFile := write(t, dir, "order.txt", "# a reference\nsec-ch-ua\nuser-agent\n")
	badOrder := write(t, dir, "bad-order.txt", "user-agent: Mozilla\n")
	empty := write(t, dir, "empty.txt", "\n\n")

	tests := []struct {
		name   string
		args   []string
		stdin  string
		code   int
		stdout []string
		stderr string
	}{
		{"nothing wrong", []string{cleanFile}, "", 0, []string{"no findings"}, ""},
		{"from stdin", []string{"-"}, clean, 0, []string{"no findings"}, ""},
		{"a bumped user-agent", []string{bumpedFile}, "", 1, []string{"error sec-ch-ua:", "version 151 while the User-Agent says Chrome 152"}, ""},
		{"a profile from another version", []string{"-profile", "chrome_146", cleanFile}, "", 1, []string{"error profile:"}, ""},
		{"an order the browser does not use", []string{"-order", orderFile, cleanFile}, "", 1, []string{"error order:"}, ""},
		{"a har", []string{"-har", harFile}, "", 1, []string{"identity 1 of 2: 2 requests, navigate", "no findings", "identity 2 of 2: 1 request, navigate", "error sec-ch-ua:"}, ""},
		{"no input", nil, "", 2, nil, "usage:"},
		{"a har and a file", []string{"-har", harFile, cleanFile}, "", 2, nil, "usage:"},
		{"a missing file", []string{filepath.Join(dir, "missing.txt")}, "", 2, nil, "missing.txt"},
		{"an empty file", []string{empty}, "", 2, nil, "no header lines"},
		{"an order file that is not one", []string{"-order", badOrder, cleanFile}, "", 2, nil, "is not a header name"},
		{"an unknown flag", []string{"-nope", cleanFile}, "", 2, nil, "flag provided but not defined"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
		if code != tt.code {
			t.Errorf("%s: exit %d, want %d\nstdout: %s\nstderr: %s", tt.name, code, tt.code, stdout.String(), stderr.String())
		}
		for _, want := range tt.stdout {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("%s: stdout lacks %q:\n%s", tt.name, want, stdout.String())
			}
		}
		if tt.stderr != "" && !strings.Contains(stderr.String(), tt.stderr) {
			t.Errorf("%s: stderr lacks %q:\n%s", tt.name, tt.stderr, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), "SECRET") {
			t.Errorf("%s: printed something from the capture that is not a header the checks read", tt.name)
		}
	}
}

func TestJSONOutput(t *testing.T) {
	dir := t.TempDir()
	harFile := write(t, dir, "capture.har", har)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-json", "-har", harFile}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	var reports []report
	if err := json.Unmarshal(stdout.Bytes(), &reports); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout.String())
	}
	if len(reports) != 2 || reports[0].Requests != 2 || len(reports[0].Findings) != 0 || reports[1].Requests != 1 {
		t.Errorf("reports: %+v", reports)
	}
	if len(reports[1].Findings) == 0 || reports[1].Findings[0].Severity != "error" || reports[1].Findings[0].Check != "sec-ch-ua" {
		t.Errorf("the bumped identity's findings: %+v", reports[1].Findings)
	}

	// A single block is the same shape with one element, so a caller can
	// read both the same way. The findings field is a list even when empty.
	stdout.Reset()
	clean := write(t, dir, "clean.txt", clean)
	if code := run([]string{"-json", clean}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"findings": []`) {
		t.Errorf("a clean block printed:\n%s", stdout.String())
	}
}
