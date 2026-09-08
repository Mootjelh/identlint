package identlint

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Identity is one distinct set of identity headers found in a capture.
type Identity struct {
	// Headers are the headers of the first request that carried this
	// identity, in the order they were sent. Only the headers the checks read
	// keep their value; every other header keeps its name and nothing else,
	// so a cookie, a referer or an authorization token never leaves the
	// capture. KeepsValue says which is which.
	Headers Headers

	// Requests is how many requests in the capture carried this identity.
	Requests int
}

// harFile is the part of a HAR this reads. Nothing else is decoded: not the
// URLs, not the cookies, not the bodies.
type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Headers []Header `json:"headers"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// identityHeaders make two requests the same identity when they agree.
// sec-fetch-mode is among them because a browser orders its headers
// differently on a navigation than on a fetch, so the two have to be held
// against different references.
var identityHeaders = []string{
	"user-agent",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-ch-ua-full-version-list",
	"sec-fetch-mode",
}

// valueKept lists the headers whose values a HAR read keeps. Each is either
// something a check reads or something that says what kind of request it
// was, and none of them can name a site, a user or a session.
var valueKept = map[string]bool{
	"user-agent":                  true,
	"accept":                      true,
	"accept-encoding":             true,
	"accept-language":             true,
	"sec-ch-ua":                   true,
	"sec-ch-ua-mobile":            true,
	"sec-ch-ua-platform":          true,
	"sec-ch-ua-full-version-list": true,
	"sec-ch-ua-arch":              true,
	"sec-ch-ua-bitness":           true,
	"sec-ch-ua-model":             true,
	"sec-ch-ua-platform-version":  true,
	"sec-ch-ua-wow64":             true,
	"sec-fetch-site":              true,
	"sec-fetch-mode":              true,
	"sec-fetch-user":              true,
	"sec-fetch-dest":              true,
	"upgrade-insecure-requests":   true,
	"sec-gpc":                     true,
	"dnt":                         true,
	"priority":                    true,
	"connection":                  true,
	"cache-control":               true,
	"pragma":                      true,
	"te":                          true,
	"sec-purpose":                 true,
}

// KeepsValue reports whether a HAR read keeps that header's value. Every
// other header is reduced to its name.
func KeepsValue(name string) bool { return valueKept[strings.ToLower(name)] }

// IdentitiesFromHAR reads a HAR and returns each distinct identity in it
// once, in order of first appearance. Two requests share an identity when
// their User-Agent, their sec-ch-ua headers and their sec-fetch-mode agree.
// Entries with no request headers at all, which is what a data: URL leaves
// behind, are skipped.
func IdentitiesFromHAR(r io.Reader) ([]Identity, error) {
	var har harFile
	if err := json.NewDecoder(r).Decode(&har); err != nil {
		return nil, fmt.Errorf("reading the HAR: %w", err)
	}
	if len(har.Log.Entries) == 0 {
		return nil, errors.New("the HAR has no entries")
	}

	index := map[string]int{}
	var out []Identity
	for _, e := range har.Log.Entries {
		h := scrub(e.Request.Headers)
		if len(h) == 0 {
			continue
		}
		key := identityKey(h)
		if i, ok := index[key]; ok {
			out[i].Requests++
			continue
		}
		index[key] = len(out)
		out = append(out, Identity{Headers: h, Requests: 1})
	}
	if len(out) == 0 {
		return nil, errors.New("no entry in the HAR carries request headers")
	}
	return out, nil
}

// scrub drops HTTP/2 pseudo-headers and blanks every value that is not kept.
func scrub(raw []Header) Headers {
	out := make(Headers, 0, len(raw))
	for _, h := range raw {
		if h.Name == "" || strings.HasPrefix(h.Name, ":") {
			continue
		}
		if !KeepsValue(h.Name) {
			h.Value = ""
		}
		out = append(out, h)
	}
	return out
}

func identityKey(h Headers) string {
	parts := make([]string, len(identityHeaders))
	for i, n := range identityHeaders {
		parts[i], _ = h.Get(n)
	}
	return strings.Join(parts, "\x00")
}
