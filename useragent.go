package identlint

import (
	"regexp"
	"strconv"
	"strings"
)

// Platform is the operating system a User-Agent names.
type Platform int

// The platforms the checks can tell apart.
const (
	UnknownPlatform Platform = iota
	Windows
	MacOS
	Linux
	ChromeOS
	Android
	IOS
)

// String names the platform the way sec-ch-ua-platform does, where it has a
// name there.
func (p Platform) String() string {
	if s, ok := platformHint[p]; ok {
		return s
	}
	return "unknown"
}

// platformHint is what sec-ch-ua-platform carries for each platform.
var platformHint = map[Platform]string{
	Windows:  "Windows",
	MacOS:    "macOS",
	Linux:    "Linux",
	ChromeOS: "Chrome OS",
	Android:  "Android",
}

// frozenToken is the platform text a reduced User-Agent carries: desktop
// since Chrome 107, Android since 110. The real OS version and CPU were
// removed then and every build sends these.
var frozenToken = map[Platform]string{
	Windows: "Windows NT 10.0; Win64; x64",
	MacOS:   "Macintosh; Intel Mac OS X 10_15_7",
	Linux:   "X11; Linux x86_64",
	Android: "Linux; Android 10; K",
}

// The Chrome major that first shipped each reduction.
const (
	frozenMinorSince    = 101 // MINOR.BUILD.PATCH became 0.0.0
	frozenDesktopSince  = 107 // the desktop platform token froze
	frozenAndroidSince  = 110 // the Android model and version froze
	zstdSince           = 123 // zstd joined accept-encoding by default
	clientHintsMajorMin = 89  // sec-ch-ua on every request
)

// UserAgent is what a Chromium User-Agent says about itself.
type UserAgent struct {
	Raw string

	// Family is chrome, edge or opera. Brave sends Chrome's User-Agent
	// unchanged and only names itself in sec-ch-ua, so it reads as chrome
	// here.
	Family string

	// Headless is set when the build announces itself as HeadlessChrome.
	Headless bool

	// Major and Version are from the Chrome/ token. Version is the whole
	// thing, which is MAJOR.0.0.0 on every build since Chrome 101.
	Major   int
	Version string

	// Platform is read off PlatformToken, the text inside the first pair of
	// parentheses.
	Platform      Platform
	PlatformToken string

	// Mobile is the Mobile token that Chrome for Android sends on phones.
	Mobile bool
}

var (
	chromeToken = regexp.MustCompile(`(HeadlessChrome|Chrome)/(\d+(?:\.\d+)*)`)
	edgeToken   = regexp.MustCompile(`\bEdg[A-Za-z]*/\d`)
	operaToken  = regexp.MustCompile(`\bOPR/\d`)
	parenToken  = regexp.MustCompile(`^[^(]*\(([^)]*)\)`)
)

// ParseUserAgent reads a Chromium User-Agent. The second result is false for
// anything else, including Chrome on iOS, which is WebKit underneath and says
// CriOS instead.
func ParseUserAgent(s string) (UserAgent, bool) {
	ua := UserAgent{Raw: s}

	m := chromeToken.FindStringSubmatch(s)
	if m == nil {
		return ua, false
	}
	ua.Headless = m[1] == "HeadlessChrome"
	ua.Version = m[2]
	major, _, _ := strings.Cut(m[2], ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		// Digits, but more of them than an int holds: not a Chrome version.
		return ua, false
	}
	ua.Major = n

	ua.Family = "chrome"
	switch {
	case edgeToken.MatchString(s):
		ua.Family = "edge"
	case operaToken.MatchString(s):
		ua.Family = "opera"
	}

	if p := parenToken.FindStringSubmatch(s); p != nil {
		ua.PlatformToken = p[1]
	}
	ua.Platform = classifyPlatform(ua.PlatformToken)
	ua.Mobile = strings.Contains(s, " Mobile")

	return ua, true
}

func classifyPlatform(token string) Platform {
	switch {
	case strings.Contains(token, "Windows NT"):
		return Windows
	case strings.Contains(token, "Macintosh"):
		return MacOS
	case strings.Contains(token, "CrOS"):
		return ChromeOS
	case strings.Contains(token, "Android"):
		// Before Linux: the token reads "Linux; Android 10; K".
		return Android
	case strings.Contains(token, "Linux"):
		return Linux
	case strings.Contains(token, "iPhone"), strings.Contains(token, "iPad"):
		return IOS
	}
	return UnknownPlatform
}

// brandFor is the name a family puts in sec-ch-ua, where the User-Agent pins
// it down. Chrome's User-Agent is shared by Brave, so for that family the
// list may say either.
func brandsFor(family string) []string {
	switch family {
	case "edge":
		return []string{"Microsoft Edge"}
	case "opera":
		return []string{"Opera"}
	default:
		return []string{"Google Chrome", "Brave"}
	}
}
