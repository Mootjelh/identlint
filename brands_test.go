package identlint

import (
	"strings"
	"testing"
)

// Five identities read off the wire. Brave 148 and 151 come from browser
// captures; Brave, Chrome and Edge 152 were captured by pointing each browser
// at a local server that keeps headers in arrival order. Headless changes
// the User-Agent token and nothing in sec-ch-ua.
var measured = []struct {
	browser string
	major   int
	brand   string
	sent    string
}{
	{"Brave 148 on macOS", 148, "Brave", `"Chromium";v="148", "Brave";v="148", "Not/A)Brand";v="99"`},
	{"Brave 151", 151, "Brave", `"Not=A?Brand";v="99", "Brave";v="151", "Chromium";v="151"`},
	{"Brave 152", 152, "Brave", `"Chromium";v="152", "Not?A_Brand";v="24", "Brave";v="152"`},
	{"Chrome 152", 152, "Google Chrome", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
	{"Edge 152", 152, "Microsoft Edge", `"Chromium";v="152", "Not?A_Brand";v="24", "Microsoft Edge";v="152"`},
}

func TestBrandListMatchesWhatBrowsersSend(t *testing.T) {
	for _, m := range measured {
		if got := FormatBrands(BrandList(m.major, m.brand, false, "")); got != m.sent {
			t.Errorf("%s:\n got  %s\n sent %s", m.browser, got, m.sent)
		}
	}
}

// The permutation table places entry i at position order[i]. Indexing the
// list by the table instead reads just as naturally and is wrong for four
// majors out of six. 148 is one of them, and the capture is what settles it.
func TestBrandOrderIsAPlacement(t *testing.T) {
	list := []string{"grease", "Chromium", "Brave"}
	ord := brandOrder(148, 3)

	selected := []string{list[ord[0]], list[ord[1]], list[ord[2]]}
	placed := make([]string, 3)
	for i, p := range ord {
		placed[p] = list[i]
	}
	if strings.Join(placed, ",") == strings.Join(selected, ",") {
		t.Fatal("148 does not separate the two readings; the control needs another major")
	}

	got := BrandList(148, "Brave", false, "")
	if got[0].Name != "Chromium" || got[1].Name != "Brave" || got[2].Name != "Not/A)Brand" {
		t.Errorf("BrandList(148) = %s", FormatBrands(got))
	}
}

// The arbitrary brand from Chromium's tables, for majors with and without a
// capture. 153 wraps the character table round to its first entry.
func TestGreaseBrandFollowsTheTables(t *testing.T) {
	tests := []struct {
		major         int
		name, version string
	}{
		{148, "Not/A)Brand", "99"},
		{149, "Not)A;Brand", "24"},
		{150, "Not;A=Brand", "8"},
		{151, "Not=A?Brand", "99"},
		{152, "Not?A_Brand", "24"},
		{153, "Not_A Brand", "8"},
	}
	for _, tt := range tests {
		got := GreaseBrand(tt.major)
		if got.Name != tt.name || got.Version != tt.version {
			t.Errorf("GreaseBrand(%d) = %s;v=%s, want %s;v=%s", tt.major, got.Name, got.Version, tt.name, tt.version)
		}
	}
}

func TestBrandListShapes(t *testing.T) {
	if got := BrandList(152, "", false, ""); len(got) != 2 {
		t.Errorf("a bare build lists %d entries, want 2: %s", len(got), FormatBrands(got))
	}
	four := BrandList(152, "Google Chrome", false, "", Brand{Name: "Extra", Version: "1"})
	if len(four) != 4 {
		t.Errorf("with an extra brand %d entries, want 4: %s", len(four), FormatBrands(four))
	}

	full := BrandList(152, "Google Chrome", true, "152.0.7364.65")
	want := map[string]string{"Chromium": "152.0.7364.65", "Google Chrome": "152.0.7364.65", "Not?A_Brand": "24.0.0.0"}
	for _, b := range full {
		if want[b.Name] != b.Version {
			t.Errorf("full list gives %s version %s, want %s", b.Name, b.Version, want[b.Name])
		}
	}
}

func TestParseBrandsRoundTrips(t *testing.T) {
	for _, m := range measured {
		list, err := ParseBrands(m.sent)
		if err != nil {
			t.Errorf("%s: %v", m.browser, err)
			continue
		}
		if got := FormatBrands(list); got != m.sent {
			t.Errorf("%s: parsed and rendered as %s", m.browser, got)
		}
	}

	// Whitespace between the pieces is tolerated; Chromium's own spacing is
	// what FormatBrands writes.
	loose, err := ParseBrands(`  "Chromium" ; v="152" ,"Brave";v="152"`)
	if err != nil || len(loose) != 2 || loose[1].Name != "Brave" {
		t.Errorf("loose spacing: %v, %v", loose, err)
	}
}

func TestParseBrandsRejectsWhatChromiumNeverWrites(t *testing.T) {
	bad := []string{
		``,
		`Chromium;v="152"`,
		`"Chromium";v=152`,
		`"Chromium";v="152",`,
		`"Chromium" "152"`,
		`"Chromium";x="152"`,
		`"Chromium`,
	}
	for _, s := range bad {
		if list, err := ParseBrands(s); err == nil {
			t.Errorf("%q parsed as %v", s, list)
		}
	}
}
