package identlint

import (
	"strings"
	"testing"
)

// The pseudo-headers each client sent, read off the wire 2026-09-25 by a
// local HTTP/2 server that decodes the HPACK block field by field: Chrome
// 153, Brave 153 and Opera GX on Chromium 152 sent the first, Firefox 156
// the second, and Go 1.26's net/http the third.
const (
	chromiumPseudo = ":method: GET\n:authority: example.test\n:scheme: https\n:path: /\n"
	firefoxPseudo  = ":method: GET\n:path: /\n:authority: example.test\n:scheme: https\n"
	goPseudo       = ":authority: example.test\n:method: GET\n:path: /\n:scheme: https\n"
)

func TestParseHeaderBlockKeepsPseudoHeaders(t *testing.T) {
	h := ParseHeaderBlock("GET / HTTP/2\n" + chromiumPseudo + "user-agent: x\n")
	var names []string
	for _, x := range h {
		names = append(names, x.Name)
	}
	if got := strings.Join(names, " "); got != ":method :authority :scheme :path user-agent" {
		t.Fatalf("got %q", got)
	}
	if v, _ := h.Get(":path"); v != "/" {
		t.Errorf(":path = %q", v)
	}
}

// Each browser's own pseudo-headers pass, the other family's and Go's are
// errors, and without an order asked for nothing is said at all: the order
// DevTools copies is not the wire order, and Go's happens to be the same one.
func TestPseudoHeaderOrder(t *testing.T) {
	chrome := identities["chrome 152 windows"]
	firefox := firefox156["navigation h1"]
	order := []string{"user-agent"}

	tests := []struct {
		name, block string
		opts        Options
		fires       bool
	}{
		{"chrome, its own", chromiumPseudo + chrome, Options{Order: order}, false},
		{"firefox, its own", firefoxPseudo + firefox, Options{Order: order}, false},
		{"chrome, firefox's", firefoxPseudo + chrome, Options{Order: order}, true},
		{"firefox, chrome's", chromiumPseudo + firefox, Options{Order: order}, true},
		{"chrome, go's", goPseudo + chrome, Options{Order: order}, true},
		{"firefox, go's", goPseudo + firefox, Options{Order: order}, true},
		{"chrome, go's, no order asked for", goPseudo + chrome, Options{}, false},
		{"chrome, only two of them", ":method: GET\n:path: /\n" + chrome, Options{Order: order}, false},
		{"chrome, a pseudo-header after a header", chromiumPseudo + chrome + "\n:protocol: websocket", Options{Order: order}, true},
	}
	for _, tt := range tests {
		findings := Check(ParseHeaderBlock(tt.block), tt.opts)
		if got := has(findings, "pseudo-order", Error); got != tt.fires {
			t.Errorf("%s: fired %v, want %v:%s", tt.name, got, tt.fires, describe(findings))
		}
		if has(findings, "order", Error) {
			t.Errorf("%s: the header order check fired on pseudo-headers:%s", tt.name, describe(findings))
		}
	}
}
