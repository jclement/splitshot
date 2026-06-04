package pdf

import (
	"bytes"
	"strings"
	"testing"
)

func filledWords(n int) []string {
	w := make([]string, n)
	for i := range w {
		w[i] = "academic"
	}
	return w
}

func TestRenderProducesValidPDF(t *testing.T) {
	cases := []struct {
		name  string
		sheet Sheet
	}{
		{"blank 20-word", Sheet{Index: 1, Total: 3, Threshold: 2, SetID: "a1b2", WordCount: 20, Tagline: "trust no single sheet"}},
		{"blank 33-word", Sheet{Index: 3, Total: 3, Threshold: 2, SetID: "a1b2", WordCount: 33}},
		{"no count sizes to default (blank Set ID fill-in line)", Sheet{Index: 1, Total: 1, Threshold: 1, SetID: ""}},
		{"filled 33-word", Sheet{Index: 2, Total: 3, Threshold: 2, SetID: "a1b2", Words: filledWords(33)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Render(c.sheet, "v1.2.3")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(out, []byte("%PDF")) {
				t.Fatalf("output is not a PDF (prefix %q)", out[:min(8, len(out))])
			}
			if len(out) < 800 {
				t.Fatalf("PDF suspiciously small: %d bytes", len(out))
			}
			if !bytes.Contains(out, []byte("%%EOF")) {
				t.Fatal("PDF missing EOF marker")
			}
			// A backup sheet must be exactly one page — the grid is scaled to
			// fit, and a stray second page is a layout bug. fpdf records the page
			// count as "/Count N" in the page tree.
			if !bytes.Contains(out, []byte("/Count 1")) {
				t.Fatal("expected a single-page PDF (/Count 1)")
			}
		})
	}
}

func TestRenderInvalidSheet(t *testing.T) {
	bad := []Sheet{
		{Index: 0, Total: 3, Threshold: 2},
		{Index: 4, Total: 3, Threshold: 2},
		{Index: 1, Total: 0, Threshold: 2},
		{Index: 1, Total: 3, Threshold: 0},
	}
	for _, s := range bad {
		if _, err := Render(s, "v0"); err == nil {
			t.Fatalf("expected error for sheet %+v", s)
		}
	}
}

func TestRenderTaglineOptional(t *testing.T) {
	// Empty tagline and empty SetID must still render (covers those branches).
	out, err := Render(Sheet{Index: 2, Total: 2, Threshold: 2, WordCount: 20}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out[:4]), "%PDF") {
		t.Fatal("not a PDF")
	}
}
