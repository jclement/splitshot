// pdf.go implements `pdf`: render printable backup sheets from shares supplied
// on stdin. Most users get PDFs via `gen --pdf`/`split --pdf`, but this lets
// you (re)generate sheets from shares you already hold.
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
	var outDir string

	cmd := &cobra.Command{
		Use:   "pdf",
		Short: "Render blank printable backup sheets from shares supplied on stdin",
		Long: "Read shares from stdin (one SLIP-0039 mnemonic per line) and write one blank PDF\n" +
			"backup sheet per share — boxes to handwrite the words into, never the words\n" +
			"themselves. The total share count (M) is inferred from the highest share index\n" +
			"seen; the threshold (N) is taken from the shares themselves.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lines, err := readShareLines(cmd.InOrStdin())
			if err != nil {
				return err
			}
			shares, err := parseShares(lines)
			if err != nil {
				return err
			}
			return renderSheets(cmd, info, shares, outDir)
		},
	}

	cmd.Flags().StringVarP(&outDir, "out", "o", ".", "directory to write the PDF backup sheets into")
	return cmd
}

// renderSheets writes one blank PDF per share. Total is inferred as the highest
// member index seen (a lower bound — these may be a subset of the full set).
func renderSheets(cmd *cobra.Command, info BuildInfo, shares []slip039.Share, outDir string) error {
	threshold := shares[0].MemberThreshold
	total := 0
	for _, s := range shares {
		if s.MemberIndex+1 > total {
			total = s.MemberIndex + 1
		}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	setID := fmt.Sprintf("%04X", shares[0].Identifier)
	for _, s := range shares {
		index := s.MemberIndex + 1
		sheet := pdf.Sheet{
			Index:     index,
			Total:     total,
			Threshold: threshold,
			SetID:     setID,
			WordCount: len(s.Words()),
			Tagline:   taglines.Pick(s.Identifier + s.MemberIndex),
		}
		data, err := pdf.Render(sheet, info.Version)
		if err != nil {
			return fmt.Errorf("rendering share %d PDF: %w", index, err)
		}
		path := filepath.Join(outDir, fmt.Sprintf("splitshot-share-%d-of-%d.pdf", index, total))
		if err := writeSecureFile(path, data); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %d backup sheet(s) to %s/ (Set ID %s)\n", len(shares), outDir, setID)
	return nil
}
