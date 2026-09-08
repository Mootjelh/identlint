package identlint

import (
	"errors"
	"fmt"
	"strings"
)

// ParseBrands parses a sec-ch-ua or sec-ch-ua-full-version-list value.
//
// The header is a structured-field list of quoted strings, each with one
// parameter: "Name";v="Version", and Chromium joins the entries with a comma
// and a space. Whitespace between the pieces is tolerated. Anything else is an
// error, and the error is a finding in its own right, since no Chromium build
// writes it.
func ParseBrands(value string) ([]Brand, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return nil, errors.New("the value is empty")
	}

	var out []Brand
	for {
		name, rest, err := quoted(s)
		if err != nil {
			return nil, err
		}
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, ";") {
			return nil, fmt.Errorf("after %q: expected ;v=, got %s", name, head(rest))
		}
		rest = strings.TrimSpace(rest[1:])
		if !strings.HasPrefix(rest, "v=") {
			return nil, fmt.Errorf("after %q: expected v=, got %s", name, head(rest))
		}
		version, rest, err := quoted(rest[2:])
		if err != nil {
			return nil, fmt.Errorf("version of %q: %w", name, err)
		}
		out = append(out, Brand{Name: name, Version: version})

		rest = strings.TrimSpace(rest)
		if rest == "" {
			return out, nil
		}
		if !strings.HasPrefix(rest, ",") {
			return nil, fmt.Errorf("after %q: expected a comma or the end, got %s", name, head(rest))
		}
		s = strings.TrimSpace(rest[1:])
		if s == "" {
			return nil, errors.New("the value ends in a comma")
		}
	}
}

// FormatBrands renders a list the way Chromium writes the header. A quote or
// a backslash inside a name is escaped, so what ParseBrands read renders back
// to something it reads the same way; Chromium itself never writes either.
func FormatBrands(brands []Brand) string {
	var b strings.Builder
	for i, br := range brands {
		if i > 0 {
			b.WriteString(", ")
		}
		writeQuoted(&b, br.Name)
		b.WriteString(";v=")
		writeQuoted(&b, br.Version)
	}
	return b.String()
}

func writeQuoted(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
}

// quoted reads a double-quoted string, with backslash escapes, from the front
// of s and returns it with whatever followed.
func quoted(s string) (string, string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", fmt.Errorf("expected a quoted string, got %s", head(s))
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", errors.New("the value ends inside an escape")
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", errors.New("a quoted string is not closed")
}

func head(s string) string {
	if s == "" {
		return "the end"
	}
	if len(s) > 16 {
		return fmt.Sprintf("%q...", s[:16])
	}
	return fmt.Sprintf("%q", s)
}

// parseFlag reads a structured-field boolean, the ?0 or ?1 that
// sec-ch-ua-mobile carries.
func parseFlag(value string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "?1":
		return true, nil
	case "?0":
		return false, nil
	}
	return false, fmt.Errorf("expected ?0 or ?1, got %s", head(value))
}

// parseString reads a structured-field string on its own, the "Windows" that
// sec-ch-ua-platform carries.
func parseString(value string) (string, error) {
	s, rest, err := quoted(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(rest) != "" {
		return "", fmt.Errorf("unexpected %s after the string", head(rest))
	}
	return s, nil
}
