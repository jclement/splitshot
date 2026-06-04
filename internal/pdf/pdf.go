// Package pdf renders per-share backup sheets for cold storage. Each sheet is
// a single-page PDF with the share's metadata, recovery instructions, and a
// numbered grid for the mnemonic words — blank for handwriting by default, or
// pre-printed. Core PDF fonts only (Helvetica/Courier), so the binary carries
// no embedded TTFs and stays lean.
package pdf

import (
	"bytes"
	"fmt"

	"github.com/go-pdf/fpdf"
)

// accent is the splitshot blue used for headers and rules (RGB).
var accent = struct{ r, g, b int }{37, 99, 235} // #2563EB

// Sheet describes one share's backup page.
//
// By default a sheet is a blank handwriting template: it carries only the
// parameters needed to label and later recover the share (which share, how many
// total, how many required, which set) plus empty boxes to write the words into
// by hand — no secret material reaches the renderer, so it cannot leak it.
//
// Words is the deliberate, opt-in exception: when non-empty, the share's words
// are PRINTED into the boxes (the `pdf -p` "trust your printer" mode). Callers
// must only populate it when the user has explicitly asked to put the secret on
// paper.
type Sheet struct {
	Index     int      // human-facing share number (1-based)
	Total     int      // M — total shares in the set
	Threshold int      // N — shares required to recover
	SetID     string   // identifier fingerprint, matches sheets of one set
	WordCount int      // how many blank word boxes to draw when Words is empty
	Words     []string // if non-empty, PRINT these words into the boxes
	Tagline   string   // a (sarcastic) tagline for the header
}

// Render produces a one-page PDF for a single share. version is stamped in the
// footer so a recovered-from-PDF user knows which tool wrote it.
func Render(s Sheet, version string) ([]byte, error) {
	if s.Total < 1 || s.Threshold < 1 || s.Index < 1 || s.Index > s.Total {
		return nil, fmt.Errorf("invalid sheet: index %d of %d, threshold %d", s.Index, s.Total, s.Threshold)
	}

	pdf := fpdf.New("P", "mm", "Letter", "")
	pdf.SetMargins(18, 18, 18)
	// Every element is positioned manually and the word grid is scaled to fit a
	// single page, so auto page-break must stay OFF — otherwise the footer (which
	// sits in the bottom margin) would spill onto a spurious second page.
	pdf.SetAutoPageBreak(false, 0)
	pdf.AddPage()

	drawHeader(pdf, s)
	drawInstructions(pdf, s)
	drawWordGrid(pdf, s)
	drawFooter(pdf, version)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("rendering PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// drawHeader renders the title, tagline, and the "#X of M (N required)" banner.
func drawHeader(pdf *fpdf.Fpdf, s Sheet) {
	pdf.SetTextColor(accent.r, accent.g, accent.b)
	pdf.SetFont("Helvetica", "B", 26)
	pdf.CellFormat(0, 12, "splitshot", "", 1, "L", false, 0, "")

	if s.Tagline != "" {
		pdf.SetTextColor(110, 110, 110)
		pdf.SetFont("Helvetica", "I", 10)
		// Core PDF fonts are cp1252; translate so any non-ASCII punctuation in a
		// tagline renders correctly rather than as mojibake.
		tr := pdf.UnicodeTranslatorFromDescriptor("")
		pdf.CellFormat(0, 6, tr(s.Tagline), "", 1, "L", false, 0, "")
	}

	pdf.Ln(3)
	pdf.SetDrawColor(accent.r, accent.g, accent.b)
	pdf.SetLineWidth(0.6)
	y := pdf.GetY()
	pdf.Line(18, y, 197, y)
	pdf.Ln(5)

	pdf.SetTextColor(20, 20, 20)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, fmt.Sprintf("Recovery Share #%d of %d", s.Index, s.Total), "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 12)
	pdf.SetTextColor(60, 60, 60)
	pdf.CellFormat(0, 7, fmt.Sprintf("Any %d of the %d shares are required to recover the secret.", s.Threshold, s.Total), "", 1, "L", false, 0, "")
	pdf.SetFont("Courier", "", 10)
	if s.SetID != "" {
		pdf.CellFormat(0, 7, "Set ID: "+s.SetID+"   (all shares in this set share this ID)", "", 1, "L", false, 0, "")
	} else {
		pdf.CellFormat(0, 7, "Set ID: ______________   (write the Set ID shown by splitshot)", "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)
}

// drawInstructions renders the recovery how-to box.
func drawInstructions(pdf *fpdf.Fpdf, s Sheet) {
	pdf.SetFillColor(244, 247, 255)
	pdf.SetDrawColor(200, 215, 245)
	pdf.SetLineWidth(0.3)
	x, y := pdf.GetX(), pdf.GetY()
	const w, h = 179.0, 34.0
	pdf.RoundedRect(x, y, w, h, 2, "1234", "FD")

	pdf.SetXY(x+4, y+3)
	pdf.SetTextColor(accent.r, accent.g, accent.b)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 6, "How to recover", "", 1, "L", false, 0, "")

	lines := []string{
		fmt.Sprintf("1. Gather any %d of the %d share sheets from this set (matching Set ID).", s.Threshold, s.Total),
		"2. Install splitshot (github.com/jclement/splitshot) on a trusted, offline machine.",
		"3. Run:  splitshot combine   and type/paste each share's words, one share per line.",
		"4. The original secret is printed once. A single share alone reveals nothing.",
	}
	pdf.SetTextColor(50, 50, 50)
	pdf.SetFont("Helvetica", "", 9.5)
	for _, ln := range lines {
		pdf.SetX(x + 4)
		pdf.CellFormat(w-8, 5.2, ln, "", 1, "L", false, 0, "")
	}
	pdf.SetY(y + h + 5)
}

// drawWordGrid renders the numbered word boxes in two columns. By default the
// boxes are empty (handwriting template); when s.Words is populated, the words
// are printed inside them. Row height is computed so the whole grid fits on the
// page regardless of the word count (20–33 words). Auto page-break is off for
// the whole sheet (see Render), so the manual positioning is never disrupted.
func drawWordGrid(pdf *fpdf.Fpdf, s Sheet) {
	filled := len(s.Words) > 0
	count := s.WordCount
	if filled {
		count = len(s.Words)
	}
	if count <= 0 {
		count = 20 // sensible default if neither words nor a count were supplied
	}

	pdf.SetTextColor(20, 20, 20)
	pdf.SetFont("Helvetica", "B", 11)
	heading := "Write your share words here, in order:"
	if filled {
		heading = "Your share words (printed below). Store this sheet like the secret itself:"
	}
	pdf.CellFormat(0, 7, heading, "", 1, "L", false, 0, "")
	pdf.Ln(1)

	const cols = 2
	perCol := (count + cols - 1) / cols

	// Auto page-break is already off for the whole sheet (see Render); the grid
	// just needs the page height to scale row height so everything fits.
	_, pageH := pdf.GetPageSize()
	startX, startY := pdf.GetX(), pdf.GetY()

	// Fit perCol rows into the remaining vertical space (leaving room for the
	// footer), capping the row height so a short list doesn't look stretched.
	const footerReserve = 26.0
	avail := pageH - startY - footerReserve
	rowH := avail / float64(perCol)
	if rowH > 11 {
		rowH = 11
	}
	boxH := rowH - 2.5
	wordFont := 11.0
	if boxH < 5 {
		wordFont = 9
	}

	const colW, gap, numW = 84.0, 11.0, 10.0
	for i := 0; i < count; i++ {
		col := i / perCol
		row := i % perCol
		x := startX + float64(col)*(colW+gap)
		y := startY + float64(row)*rowH

		pdf.SetXY(x, y)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(accent.r, accent.g, accent.b)
		pdf.CellFormat(numW-1, boxH, fmt.Sprintf("%2d.", i+1), "", 0, "R", false, 0, "")

		pdf.SetDrawColor(170, 170, 170)
		pdf.SetLineWidth(0.3)
		pdf.RoundedRect(x+numW, y, colW-numW, boxH, 1.5, "1234", "D")

		if filled && i < len(s.Words) {
			pdf.SetXY(x+numW+2, y)
			pdf.SetFont("Courier", "", wordFont)
			pdf.SetTextColor(20, 20, 20)
			pdf.CellFormat(colW-numW-3, boxH, s.Words[i], "", 0, "L", false, 0, "")
		}
	}
	pdf.SetY(startY + float64(perCol)*rowH + 4)
}

// drawFooter stamps the version and a storage reminder at the bottom.
func drawFooter(pdf *fpdf.Fpdf, version string) {
	pdf.SetY(-20)
	pdf.SetDrawColor(220, 220, 220)
	pdf.SetLineWidth(0.3)
	y := pdf.GetY()
	pdf.Line(18, y, 197, y)
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(130, 130, 130)
	pdf.CellFormat(0, 5, "Store each share in a separate location. Possession of too few shares is useless; that is the entire point.", "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, "Generated by splitshot "+version+" - SLIP-0039 Shamir secret sharing.", "", 1, "L", false, 0, "")
}
