// pdf.go implements `pdf`: generate a single multi-page printable backup PDF
// (one page per share) sized for an N-of-M split. By default the pages are
// blank templates (numbered word boxes plus the parameters) to handwrite into;
// `gen --pdf`/`split --pdf` produce the same thing alongside real shares. With
// -p it reads a secret from stdin and prints the words onto the pages.
package cli

import (
	"fmt"

	"github.com/jclement/splitshot/internal/pdf"
	"github.com/jclement/splitshot/internal/slip039"
	"github.com/jclement/splitshot/internal/taglines"
	"github.com/spf13/cobra"
)

// newPDFCmd builds the `pdf` subcommand.
func newPDFCmd(info BuildInfo) *cobra.Command {
	var (
		threshold  int
		total      int
		length     int
		outPath    string
		fill       bool
		passphrase string
		askPass    bool
	)

	cmd := &cobra.Command{
		Use:   "pdf",
		Short: "Generate a multi-page printable backup PDF for an N-of-M split",
		Long: "By default, write a single BLANK backup PDF with one page per share: numbered\n" +
			"boxes to handwrite the words into, plus the parameters (#X of M, N required, a\n" +
			"Set ID line to fill in). Nothing secret is involved; the pages are simply sized\n" +
			"for a secret of the given length.\n\n" +
			"With -p, read a secret from stdin, split it, and PRINT each share's words onto\n" +
			"its page — convenient, but it puts the secret on paper and through your printer.\n" +
			"Only use it on a trusted/offline printer. (-l is ignored with -p; the length\n" +
			"comes from the secret.)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if threshold < 2 || threshold > total || total > maxShares {
				return fmt.Errorf("need 2 ≤ -n ≤ -m ≤ %d (got n=%d, m=%d)", maxShares, threshold, total)
			}
			if fill {
				pass, err := resolvePassphrase(passphrase, askPass, true)
				if err != nil {
					return err
				}
				secretBytes, err := readSecret(cmd, "")
				if err != nil {
					return err
				}
				shares, err := slip039.Split(secretBytes, threshold, total, pass, randSource)
				if err != nil {
					return err
				}
				return writeFilledPDF(cmd, info, shares, threshold, total, outPath)
			}
			if length < 16 || length%2 != 0 {
				return fmt.Errorf("--length must be even and at least 16 (got %d)", length)
			}
			return writeBlankPDF(cmd, info, threshold, total, length, outPath)
		},
	}

	f := cmd.Flags()
	f.IntVarP(&threshold, "threshold", "n", 3, "shares required to recover (N)")
	f.IntVarP(&total, "shares", "m", 5, "total shares (M) — one page each")
	f.IntVarP(&length, "length", "l", 32, "secret length the blank pages are sized for (ignored with -p)")
	f.BoolVarP(&fill, "fill", "p", false, "read a secret from stdin, split it, and PRINT the words onto the pages")
	f.StringVar(&passphrase, "passphrase", "", "passphrase protecting the secret (with -p)")
	f.BoolVar(&askPass, "ask-passphrase", false, "prompt for the passphrase on the terminal (with -p; avoids argv/shell history)")
	f.StringVarP(&outPath, "out", "o", "splitshot-backup.pdf", "path of the backup PDF to write")

	return cmd
}

// maxShares mirrors the SLIP-0039 limit; kept local for flag validation.
const maxShares = 16

// writeBlankPDF renders a single multi-page blank backup PDF sized for a secret
// of the given length.
func writeBlankPDF(cmd *cobra.Command, info BuildInfo, threshold, total, length int, outPath string) error {
	words := slip039.WordsPerShare(length)
	sheets := make([]pdf.Sheet, total)
	for i := 0; i < total; i++ {
		sheets[i] = pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     "", // blank: a fill-in line is printed instead
			WordCount: words,
			Tagline:   taglines.Pick(i*7 + total),
		}
	}
	data, err := pdf.RenderAll(sheets, info.Version)
	if err != nil {
		return fmt.Errorf("rendering backup PDF: %w", err)
	}
	if err := writePDFFile(outPath, data); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d-page blank backup PDF to %s\n", total, outPath)
	return nil
}

// writeFilledPDF renders a single multi-page PDF with each share's words PRINTED
// on its page (the opt-in `pdf -p` mode). The file contains the secret and must
// be treated accordingly.
func writeFilledPDF(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, outPath string) error {
	setID := fmt.Sprintf("%04X", shares[0].Identifier)
	sheets := make([]pdf.Sheet, len(shares))
	for i, s := range shares {
		sheets[i] = pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     setID,
			Words:     s.Words(),
			Tagline:   taglines.Pick(s.Identifier + i),
		}
	}
	data, err := pdf.RenderAll(sheets, info.Version)
	if err != nil {
		return fmt.Errorf("rendering backup PDF: %w", err)
	}
	if err := writePDFFile(outPath, data); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(),
		"Wrote %d-page FILLED backup PDF to %s (Set ID %s) — every page holds a share's words; treat the file as the secret.\n",
		total, outPath, setID)
	return nil
}
