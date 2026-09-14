package identlint

import (
	"strings"
	"testing"
)

// Real header sets. The 152 ones came off a local server that keeps arrival
// order, from each browser started headless, which is why the User-Agent
// says HeadlessChrome; the 148 and 151 ones are from ordinary browsing
// captures. Values that name a site are left out; nothing here does.
var identities = map[string]string{
	"chrome 152 windows": `sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9`,

	"edge 152 windows": `sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Microsoft Edge";v="152"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36 Edg/152.0.0.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9`,

	"brave 152 windows": `sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Brave";v="152"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
sec-gpc: 1
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.7`,

	"edge 153 windows": `sec-ch-ua: "Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9`,

	"brave 153 windows": `sec-ch-ua: "Brave";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.0.0 Safari/537.36
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
sec-gpc: 1
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9`,

	// Opera GX is the case the brand rules got wrong. Its brand is "Opera GX",
	// not "Opera", and its own version is 135 while the Chromium it is built
	// on is 151, so a brand version cannot be held against the Chrome token.
	"opera gx 135 windows": `sec-ch-ua: "Not=A?Brand";v="99", "Opera GX";v="135", "Chromium";v="151"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/151.0.0.0 Safari/537.36 OPR/135.0.0.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7`,

	"brave 148 macos": `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="148", "Brave";v="148", "Not/A)Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
accept-language: en-GB,en;q=0.9
accept-encoding: gzip, deflate, br, zstd
sec-gpc: 1`,

	"brave 151 windows": `user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
sec-ch-ua: "Not=A?Brand";v="99", "Brave";v="151", "Chromium";v="151"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
accept-encoding: gzip, deflate, br, zstd`,

	// The same Brave 152 over HTTP/2, decoded off the frames: no host or
	// connection, priority last, and the pseudo-headers ahead of it all.
	"brave 152 windows h2": `:method: GET
:authority: 127.0.0.1:18443
:scheme: https
:path: /brave
sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Brave";v="152"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
sec-gpc: 1
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.5
priority: u=0, i`,
}

func has(findings []Finding, check string, sev Severity) bool {
	for _, f := range findings {
		if f.Check == check && f.Severity == sev {
			return true
		}
	}
	return false
}

func describe(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString("\n  " + f.Severity.String() + " " + f.Check + ": " + f.Message)
	}
	return b.String()
}

// What a browser sends has to pass. A headless build is allowed exactly the
// one warning that says so.
func TestWhatBrowsersSendPasses(t *testing.T) {
	for name, block := range identities {
		h := ParseHeaderBlock(block)
		findings := Check(h, Options{})

		for _, f := range findings {
			switch {
			case f.Severity == Error:
				t.Errorf("%s: %s: %s", name, f.Check, f.Message)
			case f.Severity == Warn && f.Check != "ua-headless":
				t.Errorf("%s: unexpected warning %s: %s", name, f.Check, f.Message)
			}
		}

		ua, _ := h.Get("user-agent")
		if headless := strings.Contains(ua, "HeadlessChrome"); headless != has(findings, "ua-headless", Warn) {
			t.Errorf("%s: headless=%v but the headless warning is %v", name, headless, !headless)
		}
	}
}

// Every rule, fired by one change to a real identity. Each case also checks
// that the unchanged identity does not produce the finding, so a rule that
// fires on everything cannot pass here.
func TestEachRuleFiresOnOneChange(t *testing.T) {
	base := identities["chrome 152 windows"]

	tests := []struct {
		name    string
		from    string
		to      string
		opts    Options
		check   string
		sev     Severity
		message string
	}{
		{
			name: "sec-ch-ua major disagrees with the User-Agent",
			from: `"Chromium";v="152"`, to: `"Chromium";v="151"`,
			check: "sec-ch-ua", sev: Error, message: "version 151",
		},
		{
			name: "the arbitrary brand copied from an old capture",
			from: `"Not?A_Brand";v="24"`, to: `"Not A;Brand";v="99"`,
			check: "sec-ch-ua", sev: Error, message: "arbitrary brand",
		},
		{
			name: "the arbitrary brand with a fixed version",
			from: `"Not?A_Brand";v="24"`, to: `"Not?A_Brand";v="99"`,
			check: "sec-ch-ua", sev: Error, message: "arbitrary brand",
		},
		{
			name:  "the brands in another major's order",
			from:  `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`,
			to:    `"Not?A_Brand";v="24", "Chromium";v="152", "Google Chrome";v="152"`,
			check: "sec-ch-ua", sev: Error, message: "orders them",
		},
		{
			name: "Edge's brand under Chrome's User-Agent",
			from: `"Google Chrome";v="152"`, to: `"Microsoft Edge";v="152"`,
			check: "sec-ch-ua", sev: Error, message: "names the browser",
		},
		{
			name:  "no arbitrary brand at all",
			from:  `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`,
			to:    `"Chromium";v="152", "Google Chrome";v="152"`,
			check: "sec-ch-ua", sev: Error, message: "no arbitrary brand",
		},
		{
			name:  "sec-ch-ua that does not parse",
			from:  `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`,
			to:    `Chromium/152`,
			check: "sec-ch-ua", sev: Error, message: "does not parse",
		},
		{
			name: "a User-Agent with the full version in it",
			from: `HeadlessChrome/152.0.0.0`, to: `HeadlessChrome/152.0.7364.65`,
			check: "ua-version", sev: Error, message: "152.0.0.0",
		},
		{
			name: "a platform the reduction removed",
			from: `Windows NT 10.0; Win64; x64`, to: `Windows NT 6.1; WOW64`,
			check: "ua-platform", sev: Warn, message: "Windows NT 10.0; Win64; x64",
		},
		{
			name: "sec-ch-ua-platform naming another OS",
			from: `sec-ch-ua-platform: "Windows"`, to: `sec-ch-ua-platform: "Linux"`,
			check: "sec-ch-ua-platform", sev: Error, message: "Windows",
		},
		{
			name: "the mobile bit on a desktop User-Agent",
			from: `sec-ch-ua-mobile: ?0`, to: `sec-ch-ua-mobile: ?1`,
			check: "sec-ch-ua-mobile", sev: Error, message: "no Mobile token",
		},
		{
			name: "accept-encoding without zstd on a build that offers it",
			from: `gzip, deflate, br, zstd`, to: `gzip, deflate, br`,
			check: "accept-encoding", sev: Warn, message: "zstd",
		},
		{
			name: "accept-encoding in another order",
			from: `gzip, deflate, br, zstd`, to: `br, gzip, deflate, zstd`,
			check: "accept-encoding", sev: Info, message: "the browser sends",
		},
		{
			name:  "a TLS profile from another major",
			opts:  Options{Profile: "chrome_146"},
			check: "profile", sev: Error, message: "Chrome 146",
		},
		{
			name:  "a TLS profile from another browser",
			opts:  Options{Profile: "firefox_148"},
			check: "profile", sev: Error, message: "firefox",
		},
		{
			name:  "a header order the reference has the other way",
			opts:  Options{Order: []string{"user-agent", "sec-ch-ua"}},
			check: "order", sev: Error, message: "user-agent is sent after sec-ch-ua",
		},
	}

	for _, tt := range tests {
		block := base
		if tt.from != "" {
			if !strings.Contains(block, tt.from) {
				t.Fatalf("%s: the base identity does not contain %q", tt.name, tt.from)
			}
			block = strings.Replace(block, tt.from, tt.to, 1)
		}

		// The control: the real identity does not produce this finding.
		if control := Check(ParseHeaderBlock(base), Options{}); has(control, tt.check, tt.sev) && tt.from != "" {
			t.Errorf("%s: the unchanged identity already reports %s", tt.name, tt.check)
			continue
		}

		findings := Check(ParseHeaderBlock(block), tt.opts)
		found := false
		for _, f := range findings {
			if f.Check == tt.check && f.Severity == tt.sev && strings.Contains(f.Message, tt.message) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no %s %s mentioning %q; got%s", tt.name, tt.sev, tt.check, tt.message, describe(findings))
		}
	}
}

func TestMissingHintsWarnOnce(t *testing.T) {
	block := strings.ReplaceAll(identities["chrome 152 windows"], `sec-ch-ua-platform: "Windows"`, "")
	block = strings.ReplaceAll(block, "sec-ch-ua-mobile: ?0", "")
	findings := Check(ParseHeaderBlock(block), Options{})
	if !has(findings, "sec-ch-ua-platform", Warn) || !has(findings, "sec-ch-ua-mobile", Warn) {
		t.Errorf("dropping the two hints beside sec-ch-ua did not warn:%s", describe(findings))
	}
}

func TestFullVersionListIsHeldToTheSameRules(t *testing.T) {
	block := identities["chrome 152 windows"] + "\n" +
		`sec-ch-ua-full-version-list: "Chromium";v="152.0.7364.65", "Not?A_Brand";v="24.0.0.0", "Google Chrome";v="152.0.7364.65"`
	if findings := Check(ParseHeaderBlock(block), Options{}); Errors(findings) {
		t.Errorf("a full version list that agrees was refused:%s", describe(findings))
	}

	wrongMajor := strings.Replace(block, `"Chromium";v="152.0.7364.65"`, `"Chromium";v="151.0.7364.65"`, 1)
	if findings := Check(ParseHeaderBlock(wrongMajor), Options{}); !has(findings, "sec-ch-ua-full-version-list", Error) {
		t.Errorf("a full version list from another major passed:%s", describe(findings))
	}

	shortVersion := strings.Replace(block, `"Chromium";v="152.0.7364.65"`, `"Chromium";v="152"`, 1)
	if findings := Check(ParseHeaderBlock(shortVersion), Options{}); !has(findings, "sec-ch-ua-full-version-list", Error) {
		t.Errorf("a major on its own in the full version list passed:%s", describe(findings))
	}
}

func TestOtherBrowsersAreLeftAlone(t *testing.T) {
	firefox := ParseHeaderBlock("user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0")
	findings := Check(firefox, Options{})
	if len(findings) != 1 || findings[0].Severity != Info {
		t.Errorf("a Firefox User-Agent got:%s", describe(findings))
	}

	if findings := Check(nil, Options{}); !has(findings, "user-agent", Error) {
		t.Errorf("no headers at all got:%s", describe(findings))
	}
}

func TestFindingsComeMostSevereFirst(t *testing.T) {
	block := strings.Replace(identities["chrome 152 windows"], `gzip, deflate, br, zstd`, `br, gzip, deflate, zstd`, 1)
	block = strings.Replace(block, `"Chromium";v="152"`, `"Chromium";v="151"`, 1)
	findings := Check(ParseHeaderBlock(block), Options{})
	for i := 1; i < len(findings); i++ {
		if findings[i].Severity > findings[i-1].Severity {
			t.Fatalf("finding %d (%s) outranks finding %d (%s)", i, findings[i].Severity, i-1, findings[i-1].Severity)
		}
	}
}

func TestParseHeaderBlockSkipsWhatIsNotAHeader(t *testing.T) {
	h := ParseHeaderBlock("GET / HTTP/1.1\n:authority: example\nUser-Agent: x\n\nAccept: */*\r\n")
	if len(h) != 2 || h[0].Name != "User-Agent" || h[1].Value != "*/*" {
		t.Errorf("got %+v", h)
	}
}
