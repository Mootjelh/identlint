// Command identlint checks that a request's headers agree with the browser
// they claim to be.
//
//	identlint headers.txt          a header block, one Name: value per line
//	identlint -                    the same, read from standard input
//	identlint -har capture.har     every distinct identity in a HAR
//
// Add -profile chrome_146 to hold the headers against a TLS profile name and
// -order FILE to hold them against a reference header order. The exit status
// is 0 when no check found an error, 1 when one did, and 2 when the input
// could not be read.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mootjelh/identlint"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// report is one identity's findings, and the shape -json prints.
type report struct {
	UserAgent string    `json:"user_agent"`
	Mode      string    `json:"mode,omitempty"`
	Requests  int       `json:"requests,omitempty"`
	Findings  []finding `json:"findings"`
}

type finding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("identlint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	harPath := fs.String("har", "", "read every distinct identity from this HAR file; - reads standard input")
	profile := fs.String("profile", "", "a TLS profile name in tls-client's spelling, such as chrome_146, to hold the headers against")
	orderPath := fs.String("order", "", "a file naming one header per line in the order the browser sends them; see orders/")
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: identlint [-profile NAME] [-order FILE] [-json] FILE|-")
		fmt.Fprintln(stderr, "       identlint [-profile NAME] [-order FILE] [-json] -har FILE|-")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := identlint.Options{Profile: *profile}
	if *orderPath != "" {
		f, err := os.Open(*orderPath)
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %v\n", err)
			return 2
		}
		opts.Order, err = identlint.ReadOrder(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %s: %v\n", *orderPath, err)
			return 2
		}
	}

	var identities []identlint.Identity
	switch {
	case *harPath != "" && fs.NArg() == 0:
		r, err := open(*harPath, stdin)
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %v\n", err)
			return 2
		}
		identities, err = identlint.IdentitiesFromHAR(r)
		r.Close()
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %s: %v\n", *harPath, err)
			return 2
		}
	case *harPath == "" && fs.NArg() == 1:
		r, err := open(fs.Arg(0), stdin)
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %v\n", err)
			return 2
		}
		text, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			fmt.Fprintf(stderr, "identlint: %s: %v\n", fs.Arg(0), err)
			return 2
		}
		h := identlint.ParseHeaderBlock(string(text))
		if len(h) == 0 {
			fmt.Fprintf(stderr, "identlint: %s: no header lines; expected Name: value, one per line\n", fs.Arg(0))
			return 2
		}
		identities = []identlint.Identity{{Headers: h}}
	default:
		fs.Usage()
		return 2
	}

	failed := false
	reports := make([]report, len(identities))
	for i, id := range identities {
		findings := identlint.Check(id.Headers, opts)
		if identlint.Errors(findings) {
			failed = true
		}
		reports[i] = describe(id, findings)
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintf(stderr, "identlint: %v\n", err)
			return 2
		}
	} else {
		printText(stdout, reports, *harPath != "")
	}
	if failed {
		return 1
	}
	return 0
}

// open returns the named file, or stdin for "-".
func open(path string, stdin io.Reader) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(stdin), nil
	}
	if path == "" {
		return nil, errors.New("no input named")
	}
	return os.Open(path)
}

func describe(id identlint.Identity, findings []identlint.Finding) report {
	ua, _ := id.Headers.Get("user-agent")
	mode, _ := id.Headers.Get("sec-fetch-mode")
	r := report{UserAgent: ua, Mode: mode, Requests: id.Requests, Findings: []finding{}}
	for _, f := range findings {
		r.Findings = append(r.Findings, finding{Check: f.Check, Severity: f.Severity.String(), Message: f.Message})
	}
	return r
}

// printText writes the findings for people. A HAR gets a line per identity
// saying which requests it stands for; a single header block gets the
// findings alone.
func printText(w io.Writer, reports []report, fromHAR bool) {
	indent := ""
	for i, r := range reports {
		if fromHAR {
			if i > 0 {
				fmt.Fprintln(w)
			}
			plural := "s"
			if r.Requests == 1 {
				plural = ""
			}
			mode := r.Mode
			if mode == "" {
				mode = "no sec-fetch-mode"
			}
			ua := r.UserAgent
			if ua == "" {
				ua = "(no User-Agent)"
			}
			fmt.Fprintf(w, "identity %d of %d: %d request%s, %s\n  %s\n", i+1, len(reports), r.Requests, plural, mode, ua)
			indent = "  "
		}
		if len(r.Findings) == 0 {
			fmt.Fprintf(w, "%sno findings\n", indent)
			continue
		}
		for _, f := range r.Findings {
			fmt.Fprintf(w, "%s%-5s %s: %s\n", indent, f.Severity, f.Check, f.Message)
		}
	}
}
