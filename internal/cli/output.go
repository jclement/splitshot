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
	"os"
	"path/filepath"

	"github.com/jclement/splitshot/internal/pdf"
	"github.com/jclement/splitshot/internal/slip039"
	"github.com/jclement/splitshot/internal/taglines"
	"github.com/spf13/cobra"
)

// shareOutput holds the output choices shared by gen and split.
type shareOutput struct {
	pdfDir string // if non-empty, write per-share PDFs here
}

// emitSecret echoes the secret with a loud warning. Interactive sessions get it
// on stdout (styled); piped runs get it on stderr so stdout stays share-only.
func emitSecret(cmd *cobra.Command, secretText string) {
	out := cmd.OutOrStdout()
	w := out
	if !isTerminal(out) {
		w = cmd.ErrOrStderr()
	}
	t := newTheme(w)
	fmt.Fprintln(w, t.warning.Render("Your secret (shown once — store or use it now, it will NOT be displayed again):"))
	fmt.Fprintln(w, "  "+t.secret.Render(secretText))
	fmt.Fprintln(w)
}

// emitShares writes the shares and, if requested, the PDF sheets.
func emitShares(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, opts shareOutput) error {
	out := cmd.OutOrStdout()
	interactive := isTerminal(out)

	if interactive {
		t := newTheme(out)
		fmt.Fprintln(out, t.heading.Render(fmt.Sprintf("Shares — any %d of %d recover the secret:", threshold, total)))
	}

	for i, s := range shares {
		writeOneShare(cmd, i, len(shares), s, interactive)
	}

	if opts.pdfDir != "" {
		return writePDFs(cmd, info, shares, threshold, total, opts)
	}
	return nil
}

// writeOneShare prints a single share mnemonic. Piped output is bare (one share
// per line, no labels, so it feeds straight into combine); interactive output
// is labeled and styled.
func writeOneShare(cmd *cobra.Command, idx, count int, s slip039.Share, interactive bool) {
	out := cmd.OutOrStdout()
	if !interactive {
		fmt.Fprintln(out, s.Mnemonic())
		return
	}
	t := newTheme(out)
	fmt.Fprintln(out, t.label.Render(fmt.Sprintf("Share %d of %d", idx+1, count)))
	fmt.Fprintln(out, "  "+t.share.Render(s.Mnemonic()))
	fmt.Fprintln(out)
}

// writePDFs renders one backup sheet per share into opts.pdfDir (0600 files).
func writePDFs(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, opts shareOutput) error {
	if err := os.MkdirAll(opts.pdfDir, 0o700); err != nil {
		return fmt.Errorf("creating PDF directory: %w", err)
	}
	setID := fmt.Sprintf("%04X", shares[0].Identifier)
	for i, s := range shares {
		sheet := pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     setID,
			WordCount: len(s.Words()),
			Tagline:   taglines.Pick(shares[0].Identifier + i),
		}
		data, err := pdf.Render(sheet, info.Version)
		if err != nil {
			return fmt.Errorf("rendering share %d PDF: %w", i+1, err)
		}
		path := filepath.Join(opts.pdfDir, fmt.Sprintf("splitshot-share-%d-of-%d.pdf", i+1, total))
		if err := writeSecureFile(path, data); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	// Notice to stderr so it never pollutes piped share output.
	fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d backup sheet(s) to %s/ (Set ID %s)\n", len(shares), opts.pdfDir, setID)
	return nil
}
