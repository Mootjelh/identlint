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
	ua, chromium := ParseUserAgent(raw)
	if !chromium {
		c.add("user-agent", Info, "not a Chromium User-Agent; only the Chromium rules exist and none of them apply")
		return
	}

	c.userAgent(ua)
	c.brands(ua)
	c.platform(ua)
	c.mobile(ua)
	c.encoding(ua)
	c.profile(ua)
	c.order()
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
			c.version(name, b, ua, full)
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
			c.version(name, b, ua, full)
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

// version holds one brand's version against the User-Agent's major.
func (c *checker) version(name string, b Brand, ua UserAgent, full bool) {
	if !full {
		if b.Version != strconv.Itoa(ua.Major) {
			c.add(name, Error, "%s gives %s version %s while the User-Agent says Chrome %d", name, b.Name, b.Version, ua.Major)
		}
		return
	}
	parts := strings.Split(b.Version, ".")
	if len(parts) != 4 {
		c.add(name, Error, "%s gives %s version %q, which is not a four-part version", name, b.Name, b.Version)
		return
	}
	if parts[0] != strconv.Itoa(ua.Major) {
		c.add(name, Error, "%s gives %s version %s while the User-Agent says Chrome %d", name, b.Name, b.Version, ua.Major)
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

	switch family {
	case "chrome", "opera":
	default:
		c.add("profile", Error, "profile %s is a %s fingerprint under a Chromium User-Agent", c.opts.Profile, family)
		return
	}
	if major != ua.Major {
		c.add("profile", Error, "profile %s is Chrome %d while the User-Agent says %d", c.opts.Profile, major, ua.Major)
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
