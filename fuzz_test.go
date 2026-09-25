package identlint

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// The seeds double as unit tests: go test runs them without -fuzz.

func FuzzParseBrands(f *testing.F) {
	for _, m := range measured {
		f.Add(m.sent)
	}
	f.Add(`"Chromium";v="152"`)
	f.Add(`"a\"b";v="1"`)
	f.Add(`"back\\slash";v="1\\"`)
	f.Add(``)
	f.Add(`"Chromium";v="152",`)
	f.Fuzz(func(t *testing.T, s string) {
		list, err := ParseBrands(s)
		if err != nil {
			return
		}
		if len(list) == 0 {
			t.Fatalf("%q parsed to an empty list without an error", s)
		}
		rendered := FormatBrands(list)
		again, err := ParseBrands(rendered)
		if err != nil {
			t.Fatalf("%q parsed, rendered as %q, and that does not parse: %v", s, rendered, err)
		}
		if FormatBrands(again) != rendered {
			t.Fatalf("%q renders as %q and re-renders as %q", s, rendered, FormatBrands(again))
		}
	})
}

func FuzzParseUserAgent(f *testing.F) {
	for _, block := range identities {
		ua, _ := ParseHeaderBlock(block).Get("user-agent")
		f.Add(ua)
	}
	f.Add("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36")
	f.Add("Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0")
	f.Add("Chrome/99999999999999999999.0.0.0")
	f.Add("Chrome/0152.0.0.0")
	f.Fuzz(func(t *testing.T, s string) {
		ua, ok := ParseUserAgent(s)
		if !ok {
			return
		}
		first, _, _ := strings.Cut(ua.Version, ".")
		if n, err := strconv.Atoi(first); err != nil || n != ua.Major || n < 0 {
			t.Fatalf("%q parsed as version %q with major %d", s, ua.Version, ua.Major)
		}
		switch ua.Family {
		case "chrome", "edge", "opera", "firefox":
		default:
			t.Fatalf("%q parsed as family %q", s, ua.Family)
		}
		if ua.Family == "firefox" && !firefoxToken.MatchString(s) {
			t.Fatalf("%q parsed as firefox without a Firefox token", s)
		}
		if ua.Family != "firefox" && ua.RvVersion != "" {
			t.Fatalf("%q parsed as family %q and still carries rv %q", s, ua.Family, ua.RvVersion)
		}
	})
}

func FuzzCheck(f *testing.F) {
	for _, block := range identities {
		f.Add(block, "chrome_152")
	}
	f.Add("user-agent: nothing", "")
	f.Add("", "firefox_1")
	f.Add("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 Chrome/1\r\n", "chrome_1")
	f.Fuzz(func(t *testing.T, block, profile string) {
		opts := Options{Profile: profile, Order: []string{"sec-ch-ua", "user-agent", "accept"}}
		findings := Check(ParseHeaderBlock(block), opts)
		for i := 1; i < len(findings); i++ {
			if findings[i].Severity > findings[i-1].Severity {
				t.Fatalf("findings are not most severe first: %v", findings)
			}
		}
	})
}

func FuzzIdentitiesFromHAR(f *testing.F) {
	f.Add([]byte(sampleHAR))
	f.Add([]byte(`{"log":{"entries":[]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"headers":[{"name":"Cookie","value":"a=b"},{"name":":authority","value":"x"}]}}]}}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ids, err := IdentitiesFromHAR(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(ids) == 0 {
			t.Fatal("no identities and no error")
		}
		for _, id := range ids {
			if id.Requests < 1 {
				t.Fatalf("an identity with %d requests", id.Requests)
			}
			for _, h := range id.Headers {
				if !KeepsValue(h.Name) && h.Value != "" {
					t.Fatalf("%s kept its value %q", h.Name, h.Value)
				}
			}
		}
	})
}
