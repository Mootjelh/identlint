package identlint

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// sampleHAR has five entries: a navigation, an image the page fetched, the
// navigation again, a data: URL with no headers, and a navigation from
// another Chrome. Everything that must never leave a capture is spelled
// SECRET so a test can look for it.
const sampleHAR = `{
  "log": {
    "version": "1.2",
    "creator": {"name": "test", "version": "1"},
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://example.test/account?session=SECRET-URL",
          "httpVersion": "h2",
          "cookies": [{"name": "sid", "value": "SECRET-COOKIE"}],
          "headers": [
            {"name": ":authority", "value": "example.test"},
            {"name": ":method", "value": "GET"},
            {"name": ":path", "value": "/account?session=SECRET-URL"},
            {"name": ":scheme", "value": "https"},
            {"name": "sec-ch-ua", "value": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\""},
            {"name": "sec-ch-ua-mobile", "value": "?0"},
            {"name": "sec-ch-ua-platform", "value": "\"Windows\""},
            {"name": "upgrade-insecure-requests", "value": "1"},
            {"name": "user-agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"},
            {"name": "accept", "value": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"name": "sec-fetch-site", "value": "none"},
            {"name": "sec-fetch-mode", "value": "navigate"},
            {"name": "sec-fetch-user", "value": "?1"},
            {"name": "sec-fetch-dest", "value": "document"},
            {"name": "accept-encoding", "value": "gzip, deflate, br, zstd"},
            {"name": "accept-language", "value": "en-US,en;q=0.9"},
            {"name": "cookie", "value": "sid=SECRET-COOKIE"}
          ]
        },
        "response": {"status": 200, "headers": [], "content": {"text": "SECRET-BODY"}}
      },
      {
        "request": {
          "method": "GET",
          "url": "https://example.test/logo.png",
          "headers": [
            {"name": "sec-ch-ua-platform", "value": "\"Windows\""},
            {"name": "user-agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"},
            {"name": "sec-ch-ua", "value": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\""},
            {"name": "sec-ch-ua-mobile", "value": "?0"},
            {"name": "accept", "value": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
            {"name": "sec-fetch-site", "value": "same-origin"},
            {"name": "sec-fetch-mode", "value": "no-cors"},
            {"name": "sec-fetch-dest", "value": "image"},
            {"name": "referer", "value": "https://example.test/account?session=SECRET-URL"},
            {"name": "accept-encoding", "value": "gzip, deflate, br, zstd"},
            {"name": "accept-language", "value": "en-US,en;q=0.9"},
            {"name": "cookie", "value": "sid=SECRET-COOKIE"}
          ]
        },
        "response": {"status": 200, "headers": [], "content": {}}
      },
      {
        "request": {
          "method": "GET",
          "url": "https://example.test/orders?session=SECRET-URL",
          "headers": [
            {"name": "sec-ch-ua", "value": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\""},
            {"name": "sec-ch-ua-mobile", "value": "?0"},
            {"name": "sec-ch-ua-platform", "value": "\"Windows\""},
            {"name": "upgrade-insecure-requests", "value": "1"},
            {"name": "user-agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"},
            {"name": "accept", "value": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"name": "sec-fetch-site", "value": "same-origin"},
            {"name": "sec-fetch-mode", "value": "navigate"},
            {"name": "sec-fetch-user", "value": "?1"},
            {"name": "sec-fetch-dest", "value": "document"},
            {"name": "referer", "value": "https://example.test/account?session=SECRET-URL"},
            {"name": "accept-encoding", "value": "gzip, deflate, br, zstd"},
            {"name": "accept-language", "value": "en-US,en;q=0.9"},
            {"name": "cookie", "value": "sid=SECRET-COOKIE-2"}
          ]
        },
        "response": {"status": 200, "headers": [], "content": {}}
      },
      {
        "request": {"method": "GET", "url": "data:image/png;base64,SECRET", "headers": []},
        "response": {"status": 200, "headers": [], "content": {}}
      },
      {
        "request": {
          "method": "GET",
          "url": "https://example.test/",
          "headers": [
            {"name": "sec-ch-ua", "value": "\"Chromium\";v=\"151\", \"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\""},
            {"name": "sec-ch-ua-mobile", "value": "?0"},
            {"name": "sec-ch-ua-platform", "value": "\"Windows\""},
            {"name": "user-agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"},
            {"name": "sec-fetch-mode", "value": "navigate"},
            {"name": "accept-encoding", "value": "gzip, deflate, br, zstd"}
          ]
        },
        "response": {"status": 200, "headers": [], "content": {}}
      }
    ]
  }
}`

func TestIdentitiesFromHARGroupsByUserAgentAndMode(t *testing.T) {
	ids, err := IdentitiesFromHAR(strings.NewReader(sampleHAR))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("got %d identities, want 3: a 152 navigation, a 152 image fetch and a 151 navigation", len(ids))
	}

	want := []struct {
		mode     string
		major    string
		requests int
	}{
		{"navigate", "152", 2},
		{"no-cors", "152", 1},
		{"navigate", "151", 1},
	}
	for i, w := range want {
		mode, _ := ids[i].Headers.Get("sec-fetch-mode")
		ua, _ := ids[i].Headers.Get("user-agent")
		if mode != w.mode || !strings.Contains(ua, "Chrome/"+w.major) || ids[i].Requests != w.requests {
			t.Errorf("identity %d: mode %q, %s, %d requests; want %s, Chrome %s, %d requests", i, mode, ua, ids[i].Requests, w.mode, w.major, w.requests)
		}
	}

	// The first request's headers are kept in the order they were sent, and
	// the pseudo-headers are not among them.
	if ids[0].Headers[0].Name != "sec-ch-ua" || len(ids[0].Headers) != 13 {
		t.Errorf("the navigation kept %d headers starting with %s; want 13 starting with sec-ch-ua", len(ids[0].Headers), ids[0].Headers[0].Name)
	}
}

func TestAHARReadKeepsNothingThatNamesTheSession(t *testing.T) {
	ids, err := IdentitiesFromHAR(strings.NewReader(sampleHAR))
	if err != nil {
		t.Fatal(err)
	}

	// The control: the headers the checks read do keep their values.
	if v, _ := ids[0].Headers.Get("user-agent"); !strings.Contains(v, "Chrome/152") {
		t.Fatalf("user-agent lost its value: %q", v)
	}
	if v, _ := ids[1].Headers.Get("sec-fetch-dest"); v != "image" {
		t.Fatalf("sec-fetch-dest lost its value: %q", v)
	}

	for _, id := range ids {
		for _, name := range []string{"cookie", "referer"} {
			if v, ok := id.Headers.Get(name); ok && v != "" {
				t.Errorf("%s kept its value %q", name, v)
			}
		}
	}
	if !ids[1].Headers.Has("referer") {
		t.Error("referer lost its name too; the order check needs it")
	}

	// Nothing spelled SECRET survives, whichever way the result is rendered.
	asJSON, _ := json.Marshal(ids)
	for _, rendered := range []string{string(asJSON), fmt.Sprintf("%+v", ids)} {
		if strings.Contains(rendered, "SECRET") {
			t.Errorf("a secret survived the read:\n%s", rendered)
		}
	}
}

func TestAHARWithoutRequestHeadersIsAnError(t *testing.T) {
	for _, tt := range []struct{ name, har string }{
		{"not json", `{"log":`},
		{"no entries", `{"log":{"entries":[]}}`},
		{"no log", `{}`},
		{"only a data URL", `{"log":{"entries":[{"request":{"url":"data:,x","headers":[]}}]}}`},
	} {
		if ids, err := IdentitiesFromHAR(strings.NewReader(tt.har)); err == nil {
			t.Errorf("%s: no error, %d identities", tt.name, len(ids))
		}
	}
}

func TestKeepsValueIsCaseInsensitive(t *testing.T) {
	if !KeepsValue("User-Agent") || !KeepsValue("SEC-CH-UA") {
		t.Error("the headers the checks read must keep their value however they are spelled")
	}
	if KeepsValue("Cookie") || KeepsValue("Authorization") || KeepsValue("X-Forwarded-For") || KeepsValue("Host") {
		t.Error("a header that can name a site or a session must not keep its value")
	}
}
