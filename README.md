# identlint

[![CI](https://github.com/Mootjelh/identlint/actions/workflows/ci.yml/badge.svg)](https://github.com/Mootjelh/identlint/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Mootjelh/identlint.svg)](https://pkg.go.dev/github.com/Mootjelh/identlint)

Checks that a request's headers agree with the browser they claim to be.

No dependencies.

## Why

A client that borrows a browser's TLS fingerprint still has to send that browser's headers, and the parts have to agree with each other. They drift apart quietly. The User-Agent gets bumped to the current Chrome while `sec-ch-ua` keeps the version it was copied with. The TLS profile stays at whatever the library shipped. A header set copied from a capture a few months old carries an arbitrary brand that no current Chrome writes. Nothing reports any of it; the request is accepted, and a server that looks sees three browsers in one request.

```
$ identlint -profile chrome_146 headers.txt
error sec-ch-ua: sec-ch-ua gives Chromium version 152 while the User-Agent says Chrome 149
error sec-ch-ua: sec-ch-ua carries the arbitrary brand "Not?A_Brand";v="24"; Chromium 149 sends "Not)A;Brand";v="24", and both the characters and the version follow the major
error sec-ch-ua: sec-ch-ua gives Brave version 152 while the User-Agent says Chrome 149
error sec-ch-ua: sec-ch-ua lists Chromium, Not?A_Brand, Brave; Chromium 149 orders them Brave, Chromium, Not)A;Brand
error profile: profile chrome_146 is Chrome 146 while the User-Agent says 149
warn  accept-encoding: accept-encoding is "gzip, deflate, br" without zstd; Chrome has offered it by default since 123
```

That header set is a real Brave 152 navigation with the User-Agent changed to 149 and zstd taken out, held against a `chrome_146` TLS profile. Every line is something a server can see without running any JavaScript.

The arbitrary brand is the part people get wrong by hand. Chromium adds an entry shaped like `"Not/A)Brand"` to every brand list, and its punctuation, its version and its position in the list all change with the major version. Chrome 148 sends `"Not/A)Brand";v="99"` last; Chrome 152 sends `"Not?A_Brand";v="24"` in the middle. A header copied from an older capture and bumped by hand keeps the old brand:

```
$ identlint headers.txt
error sec-ch-ua: sec-ch-ua gives Chromium version 148 while the User-Agent says Chrome 152
error sec-ch-ua: sec-ch-ua gives Google Chrome version 148 while the User-Agent says Chrome 152
error sec-ch-ua: sec-ch-ua carries the arbitrary brand "Not/A)Brand";v="99"; Chromium 152 sends "Not?A_Brand";v="24", and both the characters and the version follow the major
error sec-ch-ua: sec-ch-ua lists Chromium, Google Chrome, Not/A)Brand; Chromium 152 orders them Chromium, Not?A_Brand, Google Chrome
```

## Install

```bash
go install github.com/Mootjelh/identlint/cmd/identlint@latest
```

## Use

Give it a header block, one `Name: value` per line. What DevTools copies with "Copy request headers" and what `curl -v` prints both work as they are; a request line and HTTP/2 pseudo-headers are skipped.

```bash
identlint headers.txt
curl -sv https://example.com -o /dev/null 2>&1 | identlint -
```

Or a HAR. Each distinct identity in the capture is checked once, where an identity is the User-Agent, the `sec-ch-ua` headers and `sec-fetch-mode` taken together:

```
$ identlint -har capture.har
identity 1 of 2: 2 requests, navigate
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
  no findings

identity 2 of 2: 1 request, navigate
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36
  error sec-ch-ua: sec-ch-ua carries the arbitrary brand "Not=A?Brand";v="99"; Chromium 152 sends "Not?A_Brand";v="24", and both the characters and the version follow the major
  error sec-ch-ua: sec-ch-ua gives Brave version 151 while the User-Agent says Chrome 152
  error sec-ch-ua: sec-ch-ua gives Chromium version 151 while the User-Agent says Chrome 152
  error sec-ch-ua: sec-ch-ua lists Not=A?Brand, Brave, Chromium; Chromium 152 orders them Chromium, Not?A_Brand, Brave
```

A HAR read keeps the values of the headers the checks read and nothing else. Every other header keeps its name and loses its value, so a cookie, a referer or an authorization token stays in the capture. URLs, bodies and response headers are never decoded. `identlint.KeepsValue` says which headers keep their value.

Options:

- `-profile NAME` holds the headers against a TLS profile name in the spelling [tls-client](https://github.com/bogdanfinn/tls-client) uses, such as `chrome_146`. It reads the name, not the connection: a Firefox profile under a Chromium User-Agent and a Chrome profile of another major are both errors.
- `-order FILE` holds the request against a reference header order, one name per line. The check compares the relative order of the headers that appear in both the request and the file and reports the first swapped pair; a header only one side has is skipped. Two measured files ship under [`orders/`](orders/), and the comments in them say what they cover.
- `-json` prints the same findings as JSON, one object per identity.

The exit status is 0 when no check found an error, 1 when one did, and 2 when the input could not be read. Warnings do not change it.

## What it checks

| check | severity | rule |
|---|---|---|
| `user-agent` | error, info | there is one, and it is Chromium's. Anything else gets one info line and no further checks |
| `ua-version` | error | since Chrome 101 the version in the User-Agent is `MAJOR.0.0.0` |
| `ua-platform` | warn | since Chrome 107 on desktop and 110 on Android the platform text is frozen: `Windows NT 10.0; Win64; x64`, `Macintosh; Intel Mac OS X 10_15_7`, `X11; Linux x86_64`, `Linux; Android 10; K` |
| `ua-headless` | warn | the User-Agent says HeadlessChrome |
| `sec-ch-ua` | error, warn | it parses; every version matches the User-Agent's major; the arbitrary brand has the characters, the version and the position Chromium gives it for that major; the browser brand fits the User-Agent (`Edg/` is Microsoft Edge, `OPR/` is Opera, otherwise Google Chrome or Brave). Missing is a warning |
| `sec-ch-ua-full-version-list` | error | the same rules, with four-part versions |
| `sec-ch-ua-platform` | error, warn | agrees with the platform the User-Agent names. Missing beside `sec-ch-ua` is a warning |
| `sec-ch-ua-mobile` | error, warn | agrees with the Mobile token. Missing beside `sec-ch-ua` is a warning |
| `accept-encoding` | warn, info | zstd is offered from Chrome 123 and not before. Any other difference from `gzip, deflate, br, zstd` is info |
| `profile` | error, info | with `-profile`: a Chrome or Opera profile whose major matches the User-Agent |
| `order` | error | with `-order`: the relative order of the headers both sides have |

An error cannot have come from the browser the headers claim to be. A warning is very likely wrong with some legitimate way of ending up there; a headless build is the usual one. Info is an observation.

## What was measured

The brand list rules are Chromium's own, from `components/embedder_support/user_agent_utils.cc`: the arbitrary brand's characters come from a table indexed by the major, its version from a table of three, and the three entries are placed by a permutation table indexed by the major. That was checked against five identities read off the wire, Brave 148 on macOS, Brave 151, and Brave, Chrome and Edge 152 on Windows, and all five agree. They are in `brands_test.go`. The 148 one is the useful control: the permutation table is a placement, not a selection, and reading it the other way gives the wrong order for four majors out of six, 148 among them.

The header orders under `orders/` were measured on 2026-09-08 from Chrome, Edge and Brave 152 on Windows, each started headless, against local servers that keep headers in arrival order: one plain HTTP/1.1, one HTTP/1.1 over TLS, and one HTTP/2 that decodes the HPACK block field by field. Each browser made a navigation, fetched an image, ran a `fetch()` and asked for the favicon. The three browsers sent the same order everywhere, and Brave adds `sec-gpc` after `accept`. Over HTTP/2 the order is the HTTP/1.1 order without `host` and `connection`, with `priority` added last, and the pseudo-headers come as `:method :authority :scheme :path`. The image, the `fetch()` and the favicon share one order and a navigation has another, which is why there are two files; each file covers both protocols, since a header the request does not carry is skipped.

Two things the same measurement showed that are not checked. Over HTTP/1.1 Chromium writes the client hint names in lower case, `sec-ch-ua`, and every other name with capitals, `User-Agent`; HTTP/2 lower-cases everything, so a check on it would only ever fire on HTTP/1.1. And Brave's `accept-language` carried a different q value in each session, 0.5, 0.7 and 0.8 were seen, so nothing here compares that value.

The version thresholds, 101 for the version, 107 and 110 for the platform text and 123 for zstd, are Chromium's published User-Agent reduction schedule and the Chrome 123 release. The five identities above, 148 through 152, all send a reduced User-Agent and zstd.

## What is not built in

- Only Chromium. A Firefox or Safari User-Agent gets one info line and nothing else, since none of the rules apply.
- No built-in header order. What exists is two files measured on one major, one platform and headless builds, over HTTP/1.1 and HTTP/2. That is not enough to ship as a table that fails other people's requests, so the check takes a file and the files say what they cover. The pseudo-headers are not read, so their order is not checked. A proxy or a HAR export may not keep the order the browser used; hold a request against an order only when the order it shows is the order that reached the wire.
- Opera's brand name comes from Chromium's source and not from a capture. The Android platform text comes from the schedule, not from a capture. Chrome on iOS is WebKit and is not read as Chromium.
- `-profile` reads the name you give it, not the TLS connection. It does not fingerprint anything.
- `sec-ch-ua-arch`, `-bitness`, `-model`, `-platform-version` and `-wow64` are not checked.
- The full-version-list check holds the major against the User-Agent and nothing more; it does not know which builds exist.

## Library

```go
h := identlint.ParseHeaderBlock(text)
for _, f := range identlint.Check(h, identlint.Options{Profile: "chrome_146"}) {
	fmt.Println(f.Severity, f.Check, f.Message)
}
```

`identlint.IdentitiesFromHAR` reads a capture, `identlint.ReadOrder` reads an order file. For the other direction, `identlint.BrandList(152, "Google Chrome", false, "")` builds the list Chrome 152 sends and `identlint.FormatBrands` renders it as the header value.

## License

MIT.
