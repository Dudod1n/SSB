package main

import (
	"fmt"
	"strings"
)

type screen struct {
	width, height int
	rows          []string
}

func (s *screen) update(rows []line, width, height int) string {
	full := s.width != width || s.height != height || len(s.rows) != len(rows)
	var output strings.Builder
	if full {
		output.WriteString(colors["text"] + "\x1b[2J")
	}
	next := make([]string, len(rows))
	for index, row := range rows {
		var encoded strings.Builder
		for _, part := range row {
			encoded.WriteString(colors[part.role])
			encoded.WriteString(part.text)
		}
		next[index] = encoded.String()
		if !full && next[index] == s.rows[index] {
			continue
		}
		fmt.Fprintf(&output, "\x1b[%d;1H", index+1)
		output.WriteString(next[index])
	}
	s.width, s.height, s.rows = width, height, next
	return output.String()
}
