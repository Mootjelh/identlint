package identlint

import (
	"strings"
	"testing"
)

// Over HTTP/1.1, as captured 2026-09-25 from Chrome, Edge and Brave 153, Opera
// GX on Chromium 152 and Firefox 156: Chromium writes its client hints in
// lower case and every other name it sets itself with capitals, Brave spells
// Sec-GPC with GPC in capitals, and Firefox capitalises everything.
const (
	chromeH1 = `Host: 127.0.0.1:8901
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9`

	braveH1 = `sec-ch-ua: "Brave";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36
Accept: text/html
Sec-GPC: 1
Sec-Fetch-Site: none
Accept-Encoding: gzip, deflate, br, zstd`

	firefoxH1 = `Host: 127.0.0.1:8911
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i`
)

// lowerNames lower-cases the names and leaves the values alone. Lower-casing
// the whole block would turn the User-Agent into one nothing recognises, and
// the case check would then pass because it never ran.
func lowerNames(block string) string {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		if name, value, ok := strings.Cut(l, ":"); ok {
			lines[i] = strings.ToLower(name) + ":" + value
		}
	}
	return strings.Join(lines, "\n")
}

func TestHeaderCase(t *testing.T) {
	tests := []struct {
		name, block string
		fires       bool
		mentions    string
	}{
		{"chrome as sent", chromeH1, false, ""},
		{"brave as sent", braveH1, false, ""},
		{"firefox as sent", firefoxH1, false, ""},
		{"chrome, over HTTP/2 where every name is lower case", lowerNames(chromeH1), false, ""},
		{"chrome, client hints canonicalised the way Go does", strings.Replace(chromeH1, "sec-ch-ua:", "Sec-Ch-Ua:", 1), true, "Sec-Ch-Ua"},
		{"brave, Sec-GPC canonicalised the way Go does", strings.Replace(braveH1, "Sec-GPC:", "Sec-Gpc:", 1), true, "Sec-Gpc"},
		{"chrome, a lower-case name the browser sets itself", strings.Replace(chromeH1, "Accept-Encoding:", "accept-encoding:", 1), true, "accept-encoding"},
		{"firefox, a lower-case name the browser sets itself", strings.Replace(firefoxH1, "Sec-Fetch-Site:", "sec-fetch-site:", 1), true, "sec-fetch-site"},
		// A page may set Accept and Accept-Language itself, and Chromium then
		// keeps the page's spelling: 22 of 720 accept headers in 44 DevTools
		// captures were lower case. So those two are not held to a spelling.
		{"chrome, accept as a page may set it", strings.Replace(chromeH1, "Accept:", "accept:", 1), false, ""},
	}
	for _, tt := range tests {
		findings := Check(ParseHeaderBlock(tt.block), Options{})
		fired := has(findings, "header-case", Error)
		if fired != tt.fires {
			t.Errorf("%s: fired %v, want %v:%s", tt.name, fired, tt.fires, describe(findings))
			continue
		}
		if tt.fires && !strings.Contains(describe(findings), tt.mentions) {
			t.Errorf("%s: the finding does not name %s:%s", tt.name, tt.mentions, describe(findings))
		}
	}
}
