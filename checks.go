package identlint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type checker struct {
	headers Headers
	opts    Options
	out     []Finding
}

func (c *checker) add(check string, sev Severity, format string, args ...any) {
	c.out = append(c.out, Finding{Check: check, Severity: sev, Message: fmt.Sprintf(format, args...)})
}

func (c *checker) run() {
	raw, ok := c.headers.Get("user-agent")
	if !ok {
		c.add("user-agent", Error, "no User-Agent header")
		return
	}
	ua, known := ParseUserAgent(raw)
	if !known {
		c.add("user-agent", Info, "not a Chromium or Firefox User-Agent; only those rules exist and none of them apply")
		return
	}
	if ua.Family == "firefox" {
		c.firefox(ua)
		c.profile(ua)
		c.order()
		c.pseudoOrder(ua)
		c.headerCase(ua)
		return
	}

	c.userAgent(ua)
	c.brands(ua)
	c.platform(ua)
	c.mobile(ua)
	c.highEntropy(ua)
	c.encoding(ua)
	c.profile(ua)
	c.order()
	c.pseudoOrder(ua)
	c.headerCase(ua)
}

// userAgent holds the User-Agent against the reductions Chrome shipped: the
// minor version froze at 101, the desktop platform at 107, Android at 110.
func (c *checker) userAgent(ua UserAgent) {
	if want := fmt.Sprintf("%d.0.0.0", ua.Major); ua.Major >= frozenMinorSince && ua.Version != want {
		c.add("ua-version", Error, "User-Agent says Chrome/%s; every build since Chrome %d says %s and keeps the full version for sec-ch-ua-full-version-list", ua.Version, frozenMinorSince, want)
	}

	since := 0
	switch ua.Platform {
	case Windows, MacOS, Linux:
		since = frozenDesktopSince
	case Android:
		since = frozenAndroidSince
	}
	if want := frozenToken[ua.Platform]; since > 0 && ua.Major >= since && ua.PlatformToken != want {
		c.add("ua-platform", Warn, "User-Agent names the platform %q; every build since Chrome %d sends %q", ua.PlatformToken, since, want)
	}

	if ua.Headless {
		c.add("ua-headless", Warn, "User-Agent says HeadlessChrome; a headless build announces itself there and nowhere else")
	}
}

// clientHints are the User-Agent client hints. Firefox implements none of
// them, so a Firefox User-Agent carrying one is two browsers in one request.
var clientHints = []string{
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-ch-ua-platform-version",
	"sec-ch-ua-full-version-list",
	"sec-ch-ua-arch",
	"sec-ch-ua-bitness",
	"sec-ch-ua-model",
}

// firefox holds a Gecko User-Agent against what is settled about Firefox: the
// rv token carries the same version as the Firefox token, the release build
// freezes the minor at 0, and no client hint is ever sent.
func (c *checker) firefox(ua UserAgent) {
	if ua.RvVersion != "" && ua.RvVersion != ua.Version {
		c.add("ua-version", Error, "User-Agent gives rv:%s and Firefox/%s; Firefox has sent the same version in both since Firefox 4", ua.RvVersion, ua.Version)
	}
	if want := fmt.Sprintf("%d.0", ua.Major); ua.Version != want {
		c.add("ua-version", Warn, "User-Agent says Firefox/%s; a release build says %s and keeps the rest out of the User-Agent", ua.Version, want)
	}
	for _, h := range clientHints {
		if _, ok := c.headers.Get(h); ok {
			c.add("sec-ch-ua", Error, "%s is set while the User-Agent is Firefox's; Firefox implements no User-Agent client hints and sends none of them", h)
		}
	}
}

func (c *checker) brands(ua UserAgent) {
	value, ok := c.headers.Get("sec-ch-ua")
	switch {
	case !ok:
		c.add("sec-ch-ua", Warn, "no sec-ch-ua; Chromium has sent it on every request since Chrome %d", clientHintsMajorMin)
	default:
		list, err := ParseBrands(value)
		if err != nil {
			c.add("sec-ch-ua", Error, "sec-ch-ua does not parse: %v", err)
		} else {
			c.brandList("sec-ch-ua", list, ua, false)
		}
	}

	if value, ok := c.headers.Get("sec-ch-ua-full-version-list"); ok {
		list, err := ParseBrands(value)
		if err != nil {
			c.add("sec-ch-ua-full-version-list", Error, "sec-ch-ua-full-version-list does not parse: %v", err)
		} else {
			c.brandList("sec-ch-ua-full-version-list", list, ua, true)
		}
	}
}

var greaseShape = regexp.MustCompile(`^Not.A.Brand$`)

// brandList holds one brand list against the one Chromium builds for this
// User-Agent: the versions, the arbitrary brand, the browser's own brand,
// and the order of the three.
func (c *checker) brandList(name string, list []Brand, ua UserAgent, full bool) {
	if n := len(list); n < 2 || n > 4 {
		c.add(name, Error, "%s has %d entries; Chromium sends two on a bare build and three in a browser", name, n)
		return
	}

	grease := GreaseBrand(ua.Major)
	if full {
		grease.Version += ".0.0.0"
	}

	var (
		chromium, greased  bool
		brand, fullVersion string
		extra              []Brand
	)
	for _, b := range list {
		switch {
		case b.Name == "Chromium":
			chromium = true
			c.version(name, b, ua.Major, "Chrome", full)
			if full {
				fullVersion = b.Version
			}
		case greaseShape.MatchString(b.Name):
			greased = true
			if b.Name != grease.Name || b.Version != grease.Version {
				c.add(name, Error, "%s carries the arbitrary brand %s; Chromium %d sends %s, and both the characters and the version follow the major", name, FormatBrands([]Brand{b}), ua.Major, FormatBrands([]Brand{grease}))
			}
		case brand == "":
			brand = b.Name
			c.version(name, b, ua.BrandMajor, ua.BrandToken, full)
			if full && fullVersion == "" {
				fullVersion = b.Version
			}
		default:
			extra = append(extra, b)
		}
	}

	if !chromium {
		c.add(name, Error, "%s names no Chromium entry", name)
	}
	if !greased {
		c.add(name, Error, "%s has no arbitrary brand; Chromium %d adds %s to every list", name, ua.Major, FormatBrands([]Brand{grease}))
	}
	if brand != "" && !contains(brandsFor(ua.Family), brand) {
		c.add(name, Error, "%s names the browser %q while the User-Agent is %s, which sends %s", name, brand, familyName(ua.Family), oneOf(brandsFor(ua.Family)))
	}

	if chromium && greased {
		want := BrandList(ua.Major, brand, full, fullVersion, extra...)
		if !sameNames(list, want) {
			c.add(name, Error, "%s lists %s; Chromium %d orders them %s", name, names(list), ua.Major, names(want))
		}
	}
}

// version holds one brand's version against the version the User-Agent gives
// for that product. The Chromium entry follows the Chrome token; the browser's
// own entry follows its own token, and for Opera those are different numbers.
func (c *checker) version(name string, b Brand, want int, token string, full bool) {
	if !full {
		if b.Version != strconv.Itoa(want) {
			c.add(name, Error, "%s gives %s version %s while the User-Agent says %s %d", name, b.Name, b.Version, token, want)
		}
		return
	}
	parts := strings.Split(b.Version, ".")
	if len(parts) != 4 {
		c.add(name, Error, "%s gives %s version %q, which is not a four-part version", name, b.Name, b.Version)
		return
	}
	if parts[0] != strconv.Itoa(want) {
		c.add(name, Error, "%s gives %s version %s while the User-Agent says %s %d", name, b.Name, b.Version, token, want)
	}
}

func (c *checker) platform(ua UserAgent) {
	value, ok := c.headers.Get("sec-ch-ua-platform")
	if !ok {
		if c.headers.Has("sec-ch-ua") {
			c.add("sec-ch-ua-platform", Warn, "no sec-ch-ua-platform; Chromium sends it beside sec-ch-ua on every request")
		}
		return
	}
	got, err := parseString(value)
	if err != nil {
		c.add("sec-ch-ua-platform", Error, "sec-ch-ua-platform does not parse: %v", err)
		return
	}
	want, known := platformHint[ua.Platform]
	if !known {
		c.add("sec-ch-ua-platform", Info, "the User-Agent platform %q is not one this checks, so sec-ch-ua-platform %q was not compared", ua.PlatformToken, got)
		return
	}
	if got != want {
		c.add("sec-ch-ua-platform", Error, "sec-ch-ua-platform says %q while the User-Agent says %q, which is %q", got, ua.PlatformToken, want)
	}
}

func (c *checker) mobile(ua UserAgent) {
	value, ok := c.headers.Get("sec-ch-ua-mobile")
	if !ok {
		if c.headers.Has("sec-ch-ua") {
			c.add("sec-ch-ua-mobile", Warn, "no sec-ch-ua-mobile; Chromium sends it beside sec-ch-ua on every request")
		}
		return
	}
	got, err := parseFlag(value)
	if err != nil {
		c.add("sec-ch-ua-mobile", Error, "sec-ch-ua-mobile does not parse: %v", err)
		return
	}
	if got != ua.Mobile {
		token := "has no Mobile token"
		if ua.Mobile {
			token = "carries the Mobile token"
		}
		c.add("sec-ch-ua-mobile", Error, "sec-ch-ua-mobile is %s while the User-Agent %s", strings.TrimSpace(value), token)
	}
}

// highEntropyHints are the hints Chromium sends only after a site asked for
// them with Accept-CH. Measured on Chrome 155 and Edge 156 on Windows: the
// first request carries sec-ch-ua, -mobile and -platform and nothing else,
// and these arrive on the request after the opt-in.
var highEntropyHints = []string{
	"sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model",
	"sec-ch-ua-platform-version", "sec-ch-ua-wow64",
}

var windowsPlatformVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// highEntropy holds the high-entropy hints against each other and against
// the User-Agent. It only looks at the ones that are present: a request
// without them is what every first request looks like.
func (c *checker) highEntropy(ua UserAgent) {
	var sent []string
	for _, name := range highEntropyHints {
		if c.headers.Has(name) {
			sent = append(sent, name)
		}
	}
	if len(sent) == 0 {
		return
	}
	c.add("high-entropy", Info, "%s present; Chromium sends these only after the site asked for them with Accept-CH, so on a first request to a host they are a tell", strings.Join(sent, ", "))

	str := func(name string) (string, bool) {
		value, ok := c.headers.Get(name)
		if !ok {
			return "", false
		}
		got, err := parseString(value)
		if err != nil {
			c.add(name, Error, "%s does not parse: %v", name, err)
			return "", false
		}
		return got, true
	}

	if got, ok := str("sec-ch-ua-arch"); ok && got != "x86" && got != "arm" && got != "" {
		c.add("sec-ch-ua-arch", Error, "sec-ch-ua-arch is %q; Chromium reports \"x86\" or \"arm\" and puts the width in sec-ch-ua-bitness", got)
	}
	if got, ok := str("sec-ch-ua-bitness"); ok && got != "64" && got != "32" && got != "" {
		c.add("sec-ch-ua-bitness", Error, "sec-ch-ua-bitness is %q; Chromium reports \"64\" or \"32\"", got)
	}
	if got, ok := str("sec-ch-ua-model"); ok && got != "" && ua.Platform != Android {
		c.add("sec-ch-ua-model", Error, "sec-ch-ua-model is %q on %s; only Android has a model, and desktop builds send \"\"", got, ua.Platform)
	}
	if got, ok := str("sec-ch-ua-platform-version"); ok && ua.Platform == Windows && !windowsPlatformVersion.MatchString(got) {
		c.add("sec-ch-ua-platform-version", Error, "sec-ch-ua-platform-version is %q; on Windows Chromium sends three numbers, like \"19.0.0\"", got)
	}
	if value, ok := c.headers.Get("sec-ch-ua-wow64"); ok {
		got, err := parseFlag(value)
		switch {
		case err != nil:
			c.add("sec-ch-ua-wow64", Error, "sec-ch-ua-wow64 does not parse: %v", err)
		case got && ua.Platform != Windows:
			c.add("sec-ch-ua-wow64", Error, "sec-ch-ua-wow64 is ?1 on %s; WoW64 only exists on Windows", ua.Platform)
		}
	}
}

func (c *checker) encoding(ua UserAgent) {
	value, ok := c.headers.Get("accept-encoding")
	if !ok {
		return
	}

	var tokens []string
	for _, t := range strings.Split(value, ",") {
		t, _, _ = strings.Cut(strings.TrimSpace(t), ";")
		if t != "" {
			tokens = append(tokens, strings.ToLower(t))
		}
	}
	zstd := contains(tokens, "zstd")

	switch {
	case ua.Major >= zstdSince && !zstd:
		c.add("accept-encoding", Warn, "accept-encoding is %q without zstd; Chrome has offered it by default since %d", value, zstdSince)
		return
	case ua.Major < zstdSince && zstd:
		c.add("accept-encoding", Warn, "accept-encoding offers zstd; Chrome only started to at %d and the User-Agent says %d", zstdSince, ua.Major)
		return
	}

	want := "gzip, deflate, br"
	if ua.Major >= zstdSince {
		want += ", zstd"
	}
	if got := strings.Join(tokens, ", "); got != want {
		c.add("accept-encoding", Info, "accept-encoding is %q; the browser sends %q", value, want)
	}
}

var profileName = regexp.MustCompile(`^([a-z]+)(?:_[a-z]+)*_(\d+)`)

func (c *checker) profile(ua UserAgent) {
	if c.opts.Profile == "" {
		return
	}
	m := profileName.FindStringSubmatch(strings.ToLower(c.opts.Profile))
	if m == nil {
		c.add("profile", Info, "profile %q is not a name this recognises, so it was not compared", c.opts.Profile)
		return
	}
	family := m[1]
	major, _ := strconv.Atoi(m[2])

	switch {
	case ua.Family == "firefox":
		if family != "firefox" {
			c.add("profile", Error, "profile %s is a %s fingerprint under a Firefox User-Agent", c.opts.Profile, family)
			return
		}
	case family == "chrome", family == "opera":
	default:
		c.add("profile", Error, "profile %s is a %s fingerprint under a Chromium User-Agent", c.opts.Profile, family)
		return
	}
	if major != ua.Major {
		c.add("profile", Error, "profile %s is %s %d while the User-Agent says %d", c.opts.Profile, ua.BrandToken, major, ua.Major)
	}
}

// order compares the relative order of the headers that appear in both the
// request and the reference, and reports the first pair that is swapped.
func (c *checker) order() {
	if c.opts.Order == nil {
		return
	}
	pos := make(map[string]int, len(c.opts.Order))
	for i, n := range c.opts.Order {
		pos[strings.ToLower(n)] = i
	}

	last, lastName := -1, ""
	for _, h := range c.headers {
		n := strings.ToLower(h.Name)
		p, ok := pos[n]
		if !ok {
			continue
		}
		if p < last {
			c.add("order", Error, "%s is sent after %s; the reference order has it before", n, lastName)
			return
		}
		last, lastName = p, n
	}
}

// The order each family sends its HTTP/2 pseudo-headers in, read off the
// wire: Chrome, Edge and Brave 152, Chrome and Brave 153 and Opera GX on
// Chromium 152 for the first, Firefox 156 for the second. Go's net/http
// sends :authority :method :path :scheme, which is neither.
var pseudoOrders = map[string][]string{
	"chromium": {":method", ":authority", ":scheme", ":path"},
	"firefox":  {":method", ":path", ":authority", ":scheme"},
}

// pseudoOrder holds the pseudo-headers against the order the declared family
// sends them in, and checks they all come before the first regular header,
// as HTTP/2 requires. It runs only when an order was asked for, since only
// then are the headers vouched for as the order they were sent in.
func (c *checker) pseudoOrder(ua UserAgent) {
	if c.opts.Order == nil {
		return
	}
	var got []string
	regular := ""
	for _, h := range c.headers {
		if !strings.HasPrefix(h.Name, ":") {
			if regular == "" {
				regular = strings.ToLower(h.Name)
			}
			continue
		}
		n := strings.ToLower(h.Name)
		if regular != "" {
			c.add("pseudo-order", Error, "%s comes after %s; HTTP/2 sends every pseudo-header before the first regular header", n, regular)
			return
		}
		got = append(got, n)
	}
	if len(got) == 0 {
		return
	}

	family := "chromium"
	if ua.Family == "firefox" {
		family = "firefox"
	}
	want := pseudoOrders[family]
	var sent []string
	for _, n := range want {
		if contains(got, n) {
			sent = append(sent, n)
		}
	}
	var known []string
	for _, n := range got {
		if contains(want, n) {
			known = append(known, n)
		}
	}
	if strings.Join(known, " ") != strings.Join(sent, " ") {
		c.add("pseudo-order", Error, "the pseudo-headers come as %s; %s sends %s", strings.Join(got, " "), familyTitle(family), strings.Join(want, " "))
	}
}

// wireCase says how a browser spells a header name over HTTP/1.1, for the
// names only the browser can set: a page may set Accept or Accept-Language
// itself and Chromium keeps the page's spelling, but not these. It returns ""
// for any other name. Measured on Chrome, Edge and Brave 153, Opera GX on
// Chromium 152 and Firefox 156, and against the raw HTTP/1.1 requests in 44
// DevTools captures, where it matched every one of 1,509.
func wireCase(name, family string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "sec-ch-"):
		if family == "firefox" {
			return "" // Firefox sends none; the sec-ch-ua check says so.
		}
		return n
	case n == "sec-gpc":
		return "Sec-GPC"
	case strings.HasPrefix(n, "sec-fetch-"), n == "host", n == "connection",
		n == "accept-encoding", n == "referer", n == "user-agent":
		parts := strings.Split(n, "-")
		for i, p := range parts {
			if p != "" {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
		return strings.Join(parts, "-")
	}
	return ""
}

// headerCase holds the spelling of the names the browser sets itself against
// how it writes them over HTTP/1.1. A block with no capital in any name is
// HTTP/2, or carries no spelling at all, and is left alone.
func (c *checker) headerCase(ua UserAgent) {
	cased := false
	for _, h := range c.headers {
		if strings.ToLower(h.Name) != h.Name {
			cased = true
			break
		}
	}
	if !cased {
		return
	}

	family := "chromium"
	if ua.Family == "firefox" {
		family = "firefox"
	}
	var wrong []string
	for _, h := range c.headers {
		if want := wireCase(h.Name, family); want != "" && want != h.Name {
			wrong = append(wrong, fmt.Sprintf("%s as %s", h.Name, want))
		}
	}
	if len(wrong) > 0 {
		c.add("header-case", Error, "over HTTP/1.1 %s writes %s", familyTitle(family), strings.Join(wrong, ", "))
	}
}

func familyTitle(family string) string {
	if family == "firefox" {
		return "Firefox"
	}
	return "Chromium"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func oneOf(list []string) string {
	quoted := make([]string, len(list))
	for i, s := range list {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, " or ")
}

func familyName(family string) string {
	switch family {
	case "edge":
		return "Edge's, with its Edg/ token"
	case "opera":
		return "Opera's, with its OPR/ token"
	}
	return "Chrome's"
}

func names(list []Brand) string {
	out := make([]string, len(list))
	for i, b := range list {
		out[i] = b.Name
	}
	return strings.Join(out, ", ")
}

func sameNames(a, b []Brand) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
	}
	return true
}
