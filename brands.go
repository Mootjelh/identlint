package identlint

import "strconv"

// Brand is one entry of sec-ch-ua or sec-ch-ua-full-version-list.
type Brand struct {
	Name    string
	Version string
}

// The tables Chromium draws the arbitrary brand from, in Chromium's order.
// components/embedder_support/user_agent_utils.cc,
// GetGreasedUserAgentBrandVersion.
var (
	greaseChars    = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions = []string{"8", "99", "24"}
)

// GreaseBrand is the arbitrary brand Chromium adds to the list for a major
// version. Both halves are a function of the major alone: the two characters
// come out of a table indexed by it, and so does the version. So a client
// claiming Chrome 152 has to send exactly "Not?A_Brand" with version 24, one
// claiming 151 has to send "Not=A?Brand" with 99, and a fixed string copied
// from one capture is wrong for two majors out of three.
func GreaseBrand(major int) Brand {
	n := len(greaseChars)
	return Brand{
		Name:    "Not" + greaseChars[major%n] + "A" + greaseChars[(major+1)%n] + "Brand",
		Version: greaseVersions[major%len(greaseVersions)],
	}
}

// Chromium's permutation tables, GetRandomOrder. The list is built as the
// arbitrary brand, then Chromium, then the browser's own brand, and entry i of
// that list is PLACED at position order[i]. It is not an index into the list.
// Read the other way round, major 148 comes out as Brave, grease, Chromium,
// and the browser sends Chromium, Brave, grease.
var orders3 = [6][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}

var orders4 = [24][4]int{
	{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
	{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
	{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
	{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
}

func brandOrder(seed, size int) []int {
	switch size {
	case 2:
		return []int{seed % 2, (seed + 1) % 2}
	case 3:
		o := orders3[seed%len(orders3)]
		return o[:]
	case 4:
		o := orders4[seed%len(orders4)]
		return o[:]
	}
	return nil
}

// BrandList is the list Chromium sends for a major version and a browser
// brand, in the order it sends it. An empty brand is a bare Chromium build,
// which sends two entries. extra is a fourth entry some embedders add; a
// browser sends none.
//
// With full set the versions are the ones sec-ch-ua-full-version-list
// carries: fullVersion for Chromium and the brand, and the arbitrary brand's
// version padded out to four parts.
func BrandList(major int, brand string, full bool, fullVersion string, extra ...Brand) []Brand {
	grease := GreaseBrand(major)
	version := strconv.Itoa(major)
	if full {
		grease.Version += ".0.0.0"
		version = fullVersion
	}

	list := []Brand{grease, {Name: "Chromium", Version: version}}
	if brand != "" {
		list = append(list, Brand{Name: brand, Version: version})
	}
	list = append(list, extra...)
	if len(list) > 4 {
		list = list[:4]
	}

	out := make([]Brand, len(list))
	for i, pos := range brandOrder(major, len(list)) {
		out[pos] = list[i]
	}
	return out
}
