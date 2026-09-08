package identlint

import (
	"os"
	"strings"
	"testing"
)

// The image each browser fetched from the same measurement as the 152
// identities. The referer named the local server and is left out.
var subresources = map[string]string{
	"chrome 152 image": `sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
sec-ch-ua-mobile: ?0
accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
sec-fetch-site: same-origin
sec-fetch-mode: no-cors
sec-fetch-dest: image
referer:
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9`,

	"brave 152 image": `sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Brave";v="152"
sec-ch-ua-mobile: ?0
accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
sec-gpc: 1
sec-fetch-site: same-origin
sec-fetch-mode: no-cors
sec-fetch-dest: image
referer:
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.7`,

	// A fetch() over HTTP/2 from the same Chrome: the cors request uses the
	// image's order, with priority last.
	"chrome 152 fetch h2": `:method: GET
:authority: 127.0.0.1:18443
:scheme: https
:path: /api
sec-ch-ua-platform: "Windows"
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
sec-ch-ua-mobile: ?0
accept: */*
sec-fetch-site: same-origin
sec-fetch-mode: cors
sec-fetch-dest: empty
referer:
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
priority: u=1, i`,
}

func readOrderFile(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	order, err := ReadOrder(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return order
}

// The shipped order files have to agree with the identities they were
// measured from, and a file with two names swapped has to be caught. The
// second half is the control: without it a check that never fires passes.
func TestTheMeasuredOrdersFitTheMeasuredIdentities(t *testing.T) {
	cases := []struct {
		file   string
		blocks map[string]string
		names  []string
	}{
		{"orders/chromium-152-navigation.txt", identities, []string{"chrome 152 windows", "edge 152 windows", "brave 152 windows", "brave 152 windows h2"}},
		{"orders/chromium-152-subresource.txt", subresources, []string{"chrome 152 image", "brave 152 image", "chrome 152 fetch h2"}},
	}
	for _, c := range cases {
		order := readOrderFile(t, c.file)
		for _, name := range c.names {
			findings := Check(ParseHeaderBlock(c.blocks[name]), Options{Order: order})
			if has(findings, "order", Error) {
				t.Errorf("%s against %s:%s", name, c.file, describe(findings))
			}
		}

		swapped := append([]string(nil), order...)
		i, j := indexOf(swapped, "user-agent"), indexOf(swapped, "accept")
		swapped[i], swapped[j] = swapped[j], swapped[i]
		block := c.blocks[c.names[0]]
		if !has(Check(ParseHeaderBlock(block), Options{Order: swapped}), "order", Error) {
			t.Errorf("%s with user-agent and accept swapped reports nothing", c.file)
		}
	}
}

// The navigation and the subresource orders differ, which is why there are
// two files: the navigation held against the subresource order fails.
func TestANavigationDoesNotFitTheSubresourceOrder(t *testing.T) {
	order := readOrderFile(t, "orders/chromium-152-subresource.txt")
	findings := Check(ParseHeaderBlock(identities["chrome 152 windows"]), Options{Order: order})
	if !has(findings, "order", Error) {
		t.Fatal("the two orders do not separate a navigation from a subresource")
	}
}

func TestReadOrder(t *testing.T) {
	order, err := ReadOrder(strings.NewReader("# comment\n\n  Host \nUser-Agent\n"))
	if err != nil || len(order) != 2 || order[0] != "host" || order[1] != "user-agent" {
		t.Errorf("got %v, %v", order, err)
	}
	for _, bad := range []string{"", "# only a comment\n", "user-agent: Mozilla\n", "two words\n"} {
		if order, err := ReadOrder(strings.NewReader(bad)); err == nil {
			t.Errorf("%q read as %v", bad, order)
		}
	}
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}
