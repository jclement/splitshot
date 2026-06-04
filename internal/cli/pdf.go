// pdf.go implements `pdf`: generate blank printable backup sheets sized for an
// N-of-M split. No secret and no shares are involved — this just prints empty
// templates (numbered word boxes plus the parameters) to handwrite into. Most
// users get filled-in-context sheets via `gen --pdf`/`split --pdf`; this is for
// printing blanks ahead of time, or extra spares.
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

// newPDFCmd builds the `pdf` subcommand.
func newPDFCmd(info BuildInfo) *cobra.Command {
	var (
		threshold  int
		total      int
		length     int
		outDir     string
		fill       bool
		passphrase string
	)

	cmd := &cobra.Command{
		Use:   "pdf",
		Short: "Generate printable backup sheets for an N-of-M split",
		Long: "By default, write one BLANK PDF backup sheet per share: numbered boxes to\n" +
			"handwrite the words into, plus the parameters (#X of M, N required, a Set ID\n" +
			"line to fill in). Nothing secret is involved; the sheets are simply sized for a\n" +
			"secret of the given length.\n\n" +
			"With -p, read a secret from stdin, split it, and PRINT each share's words onto\n" +
			"its sheet — convenient, but it puts the secret on paper and through your\n" +
			"printer. Only use it on a trusted/offline printer. (-l is ignored with -p; the\n" +
			"length comes from the secret.)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if threshold < 2 || threshold > total || total > maxShares {
				return fmt.Errorf("need 2 ≤ -n ≤ -m ≤ %d (got n=%d, m=%d)", maxShares, threshold, total)
			}
			if fill {
				secretBytes, err := readSecret(cmd, "")
				if err != nil {
					return err
				}
				shares, err := slip039.Split(secretBytes, threshold, total, passphrase, randSource)
				if err != nil {
					return err
				}
				return writeFilledSheets(cmd, info, shares, threshold, total, outDir)
			}
			if length < 16 || length%2 != 0 {
				return fmt.Errorf("--length must be even and at least 16 (got %d)", length)
			}
			return writeBlankSheets(cmd, info, threshold, total, length, outDir)
		},
	}

	f := cmd.Flags()
	f.IntVarP(&threshold, "threshold", "n", 3, "shares required to recover (N)")
	f.IntVarP(&total, "shares", "m", 5, "total shares (M) — one sheet each")
	f.IntVarP(&length, "length", "l", 32, "secret length the blank sheets are sized for (ignored with -p)")
	f.BoolVarP(&fill, "fill", "p", false, "read a secret from stdin, split it, and PRINT the words onto the sheets")
	f.StringVar(&passphrase, "passphrase", "", "passphrase protecting the secret (with -p)")
	f.StringVarP(&outDir, "out", "o", ".", "directory to write the PDF backup sheets into")

	return cmd
}

// maxShares mirrors the SLIP-0039 limit; kept local for flag validation.
const maxShares = 16

// writeBlankSheets renders M blank sheets sized for a secret of the given
// length into outDir (0600 files).
func writeBlankSheets(cmd *cobra.Command, info BuildInfo, threshold, total, length int, outDir string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	words := slip039.WordsPerShare(length)
	for i := 0; i < total; i++ {
		sheet := pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     "", // blank: a fill-in line is printed instead
			WordCount: words,
			Tagline:   taglines.Pick(i*7 + total),
		}
		data, err := pdf.Render(sheet, info.Version)
		if err != nil {
			return fmt.Errorf("rendering sheet %d: %w", i+1, err)
		}
		path := filepath.Join(outDir, fmt.Sprintf("splitshot-share-%d-of-%d.pdf", i+1, total))
		if err := writeSecureFile(path, data); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d blank backup sheet(s) to %s/\n", total, outDir)
	return nil
}

// writeFilledSheets renders one sheet per share with the share's words PRINTED
// in the boxes (the opt-in `pdf -p` mode). These sheets contain the secret and
// must be treated accordingly.
func writeFilledSheets(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, threshold, total int, outDir string) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	setID := fmt.Sprintf("%04X", shares[0].Identifier)
	for i, s := range shares {
		sheet := pdf.Sheet{
			Index:     i + 1,
			Total:     total,
			Threshold: threshold,
			SetID:     setID,
			Words:     s.Words(),
			Tagline:   taglines.Pick(s.Identifier + i),
		}
		data, err := pdf.Render(sheet, info.Version)
		if err != nil {
			return fmt.Errorf("rendering sheet %d: %w", i+1, err)
		}
		path := filepath.Join(outDir, fmt.Sprintf("splitshot-share-%d-of-%d.pdf", i+1, total))
		if err := writeSecureFile(path, data); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(),
		"Wrote %d FILLED backup sheet(s) to %s/ (Set ID %s) — they contain your share words; treat each as the secret.\n",
		total, outDir, setID)
	return nil
}
