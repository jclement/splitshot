// gen.go implements `gen`: generate a fresh cryptographically random secret
// and split it into shares in one step. This is the common path for "I need a
// new master password / seed and I want it backed up safely from birth."
package cli

import (
	"strings"

	"github.com/jclement/splitshot/internal/secret"
	"github.com/jclement/splitshot/internal/slip039"
	"github.com/spf13/cobra"
)

// newGenCmd builds the `gen` subcommand.
func newGenCmd(info BuildInfo) *cobra.Command {
	var (
		length     int
		threshold  int
		total      int
		charset    string
		passphrase string
		pdfDir     string
		showSecret bool
	)

	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a random secret and split it into N-of-M shares",
		Long: "Generate a cryptographically secure random secret and split it into M shares,\n" +
			"any N of which reconstruct it. The secret is shown once; the shares are printed\n" +
			"(and optionally rendered to PDF backup sheets).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secretText, err := secret.Generate(length, charset, randSource)
			if err != nil {
				return err
			}
			shares, err := slip039.Split([]byte(secretText), threshold, total, passphrase, randSource)
			if err != nil {
				return err
			}
			if showSecret {
				emitSecret(cmd, secretText)
			}
			return emitShares(cmd, info, shares, threshold, total, shareOutput{pdfDir: pdfDir})
		},
	}

	f := cmd.Flags()
	f.IntVarP(&length, "length", "l", 32, "length of the generated secret (must be even and ≥16; 16→20 words, 32→33 words)")
	f.IntVarP(&threshold, "threshold", "n", 3, "shares required to recover (N)")
	f.IntVarP(&total, "shares", "m", 5, "total shares to produce (M)")
	f.StringVar(&charset, "charset", "ascii", "character set: "+strings.Join(secret.PresetNames(), ", ")+", or a literal set")
	f.StringVar(&passphrase, "passphrase", "", "optional passphrase (printable ASCII) protecting the secret")
	f.StringVar(&pdfDir, "pdf", "", "directory to write blank per-share PDF backup sheets into")
	f.BoolVar(&showSecret, "show-secret", true, "echo the generated secret (disable to only emit shares)")

	return cmd
}
