package identlint

import (
	"strings"
	"testing"
)

// The request after an Accept-CH opt-in, from Chrome 155 and Edge 156 on
// Windows 11, both started headless against a local server that asked for
// every high-entropy hint. Only the hints and the User-Agent were recorded.
var afterOptIn = map[string]string{
	"chrome 155 windows": `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/155.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"
sec-ch-ua-arch: "x86"
sec-ch-ua-bitness: "64"
sec-ch-ua-form-factors: "Desktop"
sec-ch-ua-full-version-list: "Google Chrome";v="155.0.8059.86", "Chromium";v="155.0.8059.86", "Not(A:Brand";v="24.0.0.0"
sec-ch-ua-mobile: ?0
sec-ch-ua-model: ""
sec-ch-ua-platform: "Windows"
sec-ch-ua-platform-version: "19.0.0"
sec-ch-ua-wow64: ?0`,

	"edge 156 windows": `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Microsoft Edge";v="156"
sec-ch-ua-arch: "x86"
sec-ch-ua-bitness: "64"
sec-ch-ua-form-factors: "Desktop"
sec-ch-ua-full-version-list: "Not:A-Brand";v="8.0.0.0", "Chromium";v="156.0.8078.48", "Microsoft Edge";v="156.0.4314.42"
sec-ch-ua-mobile: ?0
sec-ch-ua-model: ""
sec-ch-ua-platform: "Windows"
sec-ch-ua-platform-version: "19.0.0"
sec-ch-ua-wow64: ?0`,
}

func TestTheHighEntropyHintsBrowsersSendPass(t *testing.T) {
	for name, block := range afterOptIn {
		findings := Check(ParseHeaderBlock(block), Options{})
		for _, f := range findings {
			if f.Severity == Error || (f.Severity == Warn && f.Check != "ua-headless") {
				t.Errorf("%s: %s %s: %s", name, f.Severity, f.Check, f.Message)
			}
		}
		if !has(findings, "high-entropy", Info) {
			t.Errorf("%s: no info line saying the high-entropy hints need an opt-in", name)
		}
	}
}

// A first request carries none of them, and then there is nothing to say.
func TestAFirstRequestSaysNothingAboutHighEntropyHints(t *testing.T) {
	if f := Check(ParseHeaderBlock(identities["chrome 152 windows"]), Options{}); has(f, "high-entropy", Info) {
		t.Error("the info line fired on a request without any high-entropy hint")
	}
}

func TestEachHighEntropyRuleFiresOnOneChange(t *testing.T) {
	base := afterOptIn["chrome 155 windows"]
	tests := []struct {
		name, from, to, check, message string
	}{
		{"the arch is the Go name", `sec-ch-ua-arch: "x86"`, `sec-ch-ua-arch: "x64"`, "sec-ch-ua-arch", `"x64"`},
		{"the arch is not a string", `sec-ch-ua-arch: "x86"`, `sec-ch-ua-arch: x86`, "sec-ch-ua-arch", "does not parse"},
		{"the bitness carries the arch", `sec-ch-ua-bitness: "64"`, `sec-ch-ua-bitness: "x64"`, "sec-ch-ua-bitness", `"x64"`},
		{"a phone model on Windows", `sec-ch-ua-model: ""`, `sec-ch-ua-model: "Pixel 8"`, "sec-ch-ua-model", "only Android"},
		{"the Windows version from the User-Agent", `sec-ch-ua-platform-version: "19.0.0"`, `sec-ch-ua-platform-version: "10.0"`, "sec-ch-ua-platform-version", "three numbers"},
		{"wow64 that does not parse", `sec-ch-ua-wow64: ?0`, `sec-ch-ua-wow64: "0"`, "sec-ch-ua-wow64", "does not parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(base, tt.from) {
				t.Fatalf("the base does not contain %q", tt.from)
			}
			if has(Check(ParseHeaderBlock(base), Options{}), tt.check, Error) {
				t.Fatalf("%s already fires on the unchanged identity", tt.check)
			}
			findings := Check(ParseHeaderBlock(strings.Replace(base, tt.from, tt.to, 1)), Options{})
			for _, f := range findings {
				if f.Check == tt.check && f.Severity == Error && strings.Contains(f.Message, tt.message) {
					return
				}
			}
			t.Errorf("no %s error containing %q in %v", tt.check, tt.message, findings)
		})
	}
}

// WoW64 is a Windows mechanism, so ?1 anywhere else is a contradiction.
func TestWoW64OffWindowsIsAnError(t *testing.T) {
	mac := strings.NewReplacer(
		"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_7",
		`sec-ch-ua-platform: "Windows"`, `sec-ch-ua-platform: "macOS"`,
	).Replace(afterOptIn["chrome 155 windows"])
	if has(Check(ParseHeaderBlock(mac), Options{}), "sec-ch-ua-wow64", Error) {
		t.Fatal("the control, macOS with ?0, already fires")
	}
	if !has(Check(ParseHeaderBlock(strings.Replace(mac, "sec-ch-ua-wow64: ?0", "sec-ch-ua-wow64: ?1", 1)), Options{}), "sec-ch-ua-wow64", Error) {
		t.Error("?1 on macOS did not fire")
	}
}
