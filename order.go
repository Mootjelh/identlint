package identlint

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ReadOrder reads a reference header order: one header name per line, in
// the order the browser sends them. Blank lines and lines starting with #
// are skipped and names are lower-cased. The files under orders/ are in this
// form, and the README says how they were measured.
func ReadOrder(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t:") {
			return nil, fmt.Errorf("%q is not a header name", line)
		}
		out = append(out, strings.ToLower(line))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the order names no headers")
	}
	return out, nil
}
