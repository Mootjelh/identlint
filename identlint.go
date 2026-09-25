// Package identlint checks that the headers a client sends agree with the
// browser they claim to be.
//
// A client that borrows a browser's TLS fingerprint still has to send that
// browser's headers, and the parts have to agree with each other: the major
// version in User-Agent, in sec-ch-ua and in sec-ch-ua-full-version-list; the
// arbitrary brand Chromium adds to that list, which changes with every major
// version and sits in a position that changes with it too; the platform the
// User-Agent names against the one sec-ch-ua-platform names; the encodings
// offered against what that version of the browser offers. Each of those is
// easy to get wrong by hand and nothing reports it, which is how a client ends
// up declaring three different Chrome versions on one request.
//
// The brand list rules are Chromium's own, from
// components/embedder_support/user_agent_utils.cc, and were checked against
// what Chrome, Edge and Brave send on the wire. The README says what was
// measured and what was not.
package identlint

import (
	"sort"
	"strings"
)

// Header is one request header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Headers is a request's headers in the order they were sent. Names match
// case-insensitively; the order only matters to the check that asks for it.
type Headers []Header

// Get returns the first header with that name.
func (h Headers) Get(name string) (string, bool) {
	for _, x := range h {
		if strings.EqualFold(x.Name, name) {
			return x.Value, true
		}
	}
	return "", false
}

// Has reports whether a header with that name is present.
func (h Headers) Has(name string) bool {
	_, ok := h.Get(name)
	return ok
}

// ParseHeaderBlock reads headers from text, one per line as Name: value. A
// request line such as GET / HTTP/1.1 is skipped, so the block DevTools
// copies or curl -v prints can be pasted as it is. HTTP/2 pseudo-headers such
// as :method are kept, in place, under their own names.
func ParseHeaderBlock(text string) Headers {
	var out Headers
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		prefix := ""
		if strings.HasPrefix(line, ":") {
			prefix, line = ":", line[1:]
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, " \t") {
			// "GET / HTTP/1.1" splits on the colon in the version and lands here.
			continue
		}
		out = append(out, Header{Name: prefix + name, Value: strings.TrimSpace(value)})
	}
	return out
}

// Severity says how sure a finding is.
type Severity int

const (
	// Info is an observation, not a fault.
	Info Severity = iota
	// Warn is very likely wrong, with some legitimate way of ending up there.
	Warn
	// Error cannot have come from the browser the headers claim to be.
	Error
)

// String names the severity.
func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// Finding is one thing a check had to say.
type Finding struct {
	// Check names the rule, and is stable so it can be grepped for.
	Check    string
	Severity Severity
	Message  string
}

// Options steers Check.
type Options struct {
	// Profile is a TLS profile name in the spelling tls-client uses, such as
	// chrome_146, to hold the declared browser against. Empty skips it.
	Profile string

	// Order is a reference header order to compare against, lower-case names
	// in the order the browser sends them. Nil skips it. There is no built-in
	// order: the README says what was measured and why that is not a table
	// yet. ReadOrder reads one from a file.
	//
	// Setting it also says the headers are in the order they were sent, so
	// the HTTP/2 pseudo-headers are then held against the order the declared
	// browser family sends them in. Without it they are not: DevTools lists
	// them sorted by name, which happens to be Go's own order too.
	Order []string
}

// Check runs every rule over the headers. Findings come back most severe
// first and otherwise in the order the rules ran.
func Check(h Headers, opts Options) []Finding {
	c := &checker{headers: h, opts: opts}
	c.run()
	sort.SliceStable(c.out, func(i, j int) bool { return c.out[i].Severity > c.out[j].Severity })
	return c.out
}

// Errors reports whether any finding is an Error.
func Errors(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == Error {
			return true
		}
	}
	return false
}
