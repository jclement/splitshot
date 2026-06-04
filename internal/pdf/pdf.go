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

// Retro / Turbo-Vision-ish palette: monospace type, black borders, grey shaded
// panels, an inverse title bar. Mostly greyscale with one dark "chrome" tone.
type rgb struct{ r, g, b int }

var (
	cInk    = rgb{24, 24, 24}    // near-black: borders, body text
	cBarBg  = rgb{26, 28, 38}    // title bar / heading-tab background (dark)
	cBarTx  = rgb{240, 240, 240} // text on the dark bar (light)
	cPanel  = rgb{224, 224, 224} // shaded panel fill (grey)
	cBoxFil = rgb{245, 245, 245} // word-box fill (very light grey)
	cDim    = rgb{110, 110, 110} // secondary grey text
	cRule   = rgb{150, 150, 150} // grey rules / box borders
)

func setDraw(pdf *fpdf.Fpdf, c rgb) { pdf.SetDrawColor(c.r, c.g, c.b) }
func setFill(pdf *fpdf.Fpdf, c rgb) { pdf.SetFillColor(c.r, c.g, c.b) }
func setText(pdf *fpdf.Fpdf, c rgb) { pdf.SetTextColor(c.r, c.g, c.b) }

// Page geometry (mm, Letter, 18mm margins).
const (
	pageLeft  = 18.0
	pageRight = 197.0
	pageWidth = pageRight - pageLeft // 179
)

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
	return RenderAll([]Sheet{s}, version)
}

// RenderAll produces a single PDF with one page per sheet — the whole backup
// set in one file. version is stamped in each footer.
func RenderAll(sheets []Sheet, version string) ([]byte, error) {
	if len(sheets) == 0 {
		return nil, fmt.Errorf("no sheets to render")
	}

	pdf := fpdf.New("P", "mm", "Letter", "")
	pdf.SetMargins(18, 18, 18)
	// Every element is positioned manually and each grid is scaled to fit its
	// page, so auto page-break must stay OFF — otherwise a footer (which sits in
	// the bottom margin) would spill onto a spurious extra page.
	pdf.SetAutoPageBreak(false, 0)

	for _, s := range sheets {
		if s.Total < 1 || s.Threshold < 1 || s.Index < 1 || s.Index > s.Total {
			return nil, fmt.Errorf("invalid sheet: index %d of %d, threshold %d", s.Index, s.Total, s.Threshold)
		}
		pdf.AddPage()
		drawHeader(pdf, s)
		drawInstructions(pdf, s)
		drawWordGrid(pdf, s)
		drawFooter(pdf, version)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("rendering PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// drawHeader renders the inverse title bar, the tagline, and the share banner.
func drawHeader(pdf *fpdf.Fpdf, s Sheet) {
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	// Title bar: a solid dark band with the app name reversed out of it, like a
	// Turbo Vision window caption.
	const barH = 13.0
	y := pdf.GetY()
	setFill(pdf, cBarBg)
	setDraw(pdf, cInk)
	pdf.SetLineWidth(0.4)
	pdf.Rect(pageLeft, y, pageWidth, barH, "FD")

	setText(pdf, cBarTx)
	pdf.SetFont("Courier", "B", 22)
	pdf.SetXY(pageLeft+3, y+1)
	pdf.CellFormat(pageWidth-6, barH-2, "splitshot", "", 0, "L", false, 0, "")
	// Right-aligned share marker on the same bar, e.g. "[ 1/5 ]".
	pdf.SetFont("Courier", "B", 13)
	pdf.SetXY(pageLeft+3, y+1)
	pdf.CellFormat(pageWidth-6, barH-2, fmt.Sprintf("[ %d/%d ]", s.Index, s.Total), "", 0, "R", false, 0, "")
	pdf.SetY(y + barH)

	if s.Tagline != "" {
		setText(pdf, cDim)
		pdf.SetFont("Courier", "", 9)
		pdf.Ln(1.5)
		pdf.CellFormat(0, 5, tr(s.Tagline), "", 1, "L", false, 0, "")
	}
	pdf.Ln(2.5)

	setText(pdf, cInk)
	pdf.SetFont("Courier", "B", 17)
	pdf.CellFormat(0, 9, fmt.Sprintf("RECOVERY SHARE #%d OF %d", s.Index, s.Total), "", 1, "L", false, 0, "")

	pdf.SetFont("Courier", "", 11)
	setText(pdf, cInk)
	pdf.CellFormat(0, 6, fmt.Sprintf("Any %d of the %d shares reconstruct the secret.", s.Threshold, s.Total), "", 1, "L", false, 0, "")
	pdf.SetFont("Courier", "", 10)
	setText(pdf, cDim)
	if s.SetID != "" {
		pdf.CellFormat(0, 6, "SET ID: "+s.SetID+"   (shared by every sheet in this set)", "", 1, "L", false, 0, "")
	} else {
		pdf.CellFormat(0, 6, "SET ID: ______________   (write the Set ID shown by splitshot)", "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)
}

// drawInstructions renders the recovery how-to panel: a grey shaded box with a
// black border and an inverse title tab.
func drawInstructions(pdf *fpdf.Fpdf, s Sheet) {
	x, y := pageLeft, pdf.GetY()
	const w, h, tabH = pageWidth, 34.0, 6.0

	// Shaded panel + black border.
	setFill(pdf, cPanel)
	setDraw(pdf, cInk)
	pdf.SetLineWidth(0.4)
	pdf.Rect(x, y, w, h, "FD")

	// Inverse title tab across the top.
	setFill(pdf, cBarBg)
	pdf.Rect(x, y, w, tabH, "F")
	setText(pdf, cBarTx)
	pdf.SetFont("Courier", "B", 9)
	pdf.SetXY(x+2, y+0.5)
	pdf.CellFormat(w-4, tabH-1, "HOW TO RECOVER", "", 0, "L", false, 0, "")

	lines := []string{
		fmt.Sprintf("1. Gather any %d of the %d sheets from this set (matching Set ID).", s.Threshold, s.Total),
		"2. Install splitshot (github.com/jclement/splitshot) on a trusted, offline box.",
		"3. Run:  splitshot combine   then type each sheet's words, one sheet per line.",
		"4. The secret prints once. Fewer than the threshold of sheets reveal nothing.",
	}
	setText(pdf, cInk)
	pdf.SetFont("Courier", "", 9)
	pdf.SetXY(x+3, y+tabH+1.5)
	for _, ln := range lines {
		pdf.SetX(x + 3)
		pdf.CellFormat(w-6, 5.0, ln, "", 1, "L", false, 0, "")
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

	setText(pdf, cInk)
	pdf.SetFont("Courier", "B", 10)
	heading := "WRITE YOUR SHARE WORDS HERE, IN ORDER:"
	if filled {
		heading = "YOUR SHARE WORDS (PRINTED BELOW). STORE THIS SHEET LIKE THE SECRET ITSELF:"
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

	const colW, gap, numW = 84.0, 11.0, 11.0
	for i := 0; i < count; i++ {
		col := i / perCol
		row := i % perCol
		x := startX + float64(col)*(colW+gap)
		y := startY + float64(row)*rowH

		// Zero-padded number label.
		pdf.SetXY(x, y)
		pdf.SetFont("Courier", "B", 9)
		setText(pdf, cInk)
		pdf.CellFormat(numW-1.5, boxH, fmt.Sprintf("%02d", i+1), "", 0, "R", false, 0, "")

		// Square shaded box with a black border (a TV-style input field).
		setFill(pdf, cBoxFil)
		setDraw(pdf, cInk)
		pdf.SetLineWidth(0.3)
		pdf.Rect(x+numW, y, colW-numW, boxH, "FD")

		if filled && i < len(s.Words) {
			pdf.SetXY(x+numW+2, y)
			pdf.SetFont("Courier", "B", wordFont)
			setText(pdf, cInk)
			pdf.CellFormat(colW-numW-3, boxH, s.Words[i], "", 0, "L", false, 0, "")
		}
	}
	pdf.SetY(startY + float64(perCol)*rowH + 4)
}

// drawFooter stamps the version and a storage reminder at the bottom.
func drawFooter(pdf *fpdf.Fpdf, version string) {
	pdf.SetY(-20)
	setDraw(pdf, cRule)
	pdf.SetLineWidth(0.3)
	y := pdf.GetY()
	pdf.Line(pageLeft, y, pageRight, y)
	pdf.Ln(2)
	pdf.SetFont("Courier", "", 8)
	setText(pdf, cDim)
	pdf.CellFormat(0, 5, "Store each sheet in a separate place. Too few sheets are useless -- that is the point.", "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, "Generated by splitshot "+version+" -- SLIP-0039 Shamir secret sharing.", "", 1, "L", false, 0, "")
}
