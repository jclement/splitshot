// output.go renders the shared results of `gen` and `split`: the (optional)
// secret echo, the share list, and the optional PDF backup sheets.
//
// Output discipline: the share material goes to STDOUT (bare and one-per-line
// when piped, so it feeds straight back into `combine`), while all human-facing
// chrome — banners, the secret, warnings, PDF notices — goes to STDERR. That
// keeps `splitshot gen ... > shares.txt` clean.
package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jclement/splitshot/internal/pdf"
	"github.com/jclement/splitshot/internal/slip039"
	"github.com/jclement/splitshot/internal/taglines"
	"github.com/spf13/cobra"
)

// shareOutput holds the output choices shared by gen and split.
type shareOutput struct {
	pdfPath string // if non-empty, write a single multi-page backup PDF here
}

// emitSecret echoes the secret with a loud warning. Interactive sessions get it
// in a styled box on stdout; piped runs get it plain on stderr so stdout stays
// share-only.
func emitSecret(cmd *cobra.Command, secretText string) {
	if !isTerminal(cmd.OutOrStdout()) {
		w := cmd.ErrOrStderr()
		t := newTheme(w)
		fmt.Fprintln(w, t.warning.Render("Your secret (shown once — store or use it now, it will NOT be displayed again):"))
		fmt.Fprintln(w, "  "+t.secret.Render(secretText))
		fmt.Fprintln(w)
		return
	}
	out := cmd.OutOrStdout()
	t := newTheme(out)
	fmt.Fprintln(out, t.warning.Render("Your secret — shown once. Store or use it now; it will NOT be shown again."))
	fmt.Fprintln(out, t.secretBox.Render(t.secret.Render(secretText)))
	fmt.Fprintln(out)
}

// renderWordGrid lays the words out in an aligned, numbered grid, row-major,
// using as many columns as the terminal width allows (fewer rows on wider
// terminals). Numbers are faint, words accent-colored; each cell is a fixed
// display width so columns line up even with color codes.
func renderWordGrid(t theme, words []string, width int) string {
	// Cell holds "NN: " (4) + a word (≤8 chars in SLIP-0039) + a little gap.
	const cellWidth = 14
	const indent = 2
	cols := (width - indent) / cellWidth
	if cols < 1 {
		cols = 1
	}
	if cols > len(words) {
		cols = len(words)
	}
	cell := t.r.NewStyle().Width(cellWidth)

	var b strings.Builder
	for i := 0; i < len(words); i += cols {
		var rowCells []string
		for c := 0; c < cols && i+c < len(words); c++ {
			n := i + c
			text := t.gridNum.Render(fmt.Sprintf("%02d:", n+1)) + " " + t.share.Render(words[n])
			rowCells = append(rowCells, cell.Render(text))
		}
		b.WriteString(strings.Repeat(" ", indent) + lipgloss.JoinHorizontal(lipgloss.Top, rowCells...) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// emitShares writes the shares and, if requested, the PDF sheets. Piped output
// is bare (one mnemonic per line, so it feeds straight into combine); a terminal
// gets a labeled, numbered, width-adaptive grid per share.
func emitShares(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, opts shareOutput) error {
	out := cmd.OutOrStdout()

	if !isTerminal(out) {
		for _, s := range shares {
			fmt.Fprintln(out, s.Mnemonic())
		}
	} else {
		t := newTheme(out)
		width := terminalWidth(out)
		fmt.Fprintln(out, t.heading.Render(fmt.Sprintf("Shares — any %d of %d recover the secret:", threshold, total)))
		fmt.Fprintln(out)
		for i, s := range shares {
			words := s.Words()
			fmt.Fprintln(out, t.label.Render(fmt.Sprintf("Share %d of %d", i+1, len(shares)))+
				t.gridNum.Render(fmt.Sprintf("  (%d words)", len(words))))
			fmt.Fprintln(out, renderWordGrid(t, words, width))
			fmt.Fprintln(out)
		}
	}

	if opts.pdfPath != "" {
		return writePDFs(cmd, info, shares, threshold, total, opts)
	}
	return nil
}

// writePDFs renders all shares into a single multi-page backup PDF at
// opts.pdfPath (0600). The boxes are blank (handwriting template).
func writePDFs(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, opts shareOutput) error {
	setID := fmt.Sprintf("%04X", shares[0].Identifier)
	sheets := make([]pdf.Sheet, len(shares))
	for i, s := range shares {
		sheets[i] = pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     setID,
			WordCount: len(s.Words()),
			Tagline:   taglines.Pick(shares[0].Identifier + i),
		}
	}
	data, err := pdf.RenderAll(sheets, info.Version)
	if err != nil {
		return fmt.Errorf("rendering backup PDF: %w", err)
	}
	if err := writePDFFile(opts.pdfPath, data); err != nil {
		return err
	}
	// Notice to stderr so it never pollutes piped share output.
	fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d-page backup PDF to %s (Set ID %s)\n", len(sheets), opts.pdfPath, setID)
	return nil
}
