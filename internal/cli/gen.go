// gen.go implements `gen`: generate a fresh cryptographically random secret
// and split it into shares in one step. This is the common path for "I need a
// new master password / seed and I want it backed up safely from birth."
package cli

import (
	"fmt"
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
		askPass    bool
		pdfPath    string
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
			// Validate up front for a clear message (Split enforces the same
			// rule downstream, but later and less obviously).
			if length < 16 || length%2 != 0 {
				return fmt.Errorf("--length must be even and at least 16 (got %d)", length)
			}
			pass, err := resolvePassphrase(passphrase, askPass, true)
			if err != nil {
				return err
			}
			secretText, err := secret.Generate(length, charset, randSource)
			if err != nil {
				return err
			}
			shares, err := slip039.Split([]byte(secretText), threshold, total, pass, randSource)
			if err != nil {
				return err
			}
			if showSecret {
				emitSecret(cmd, secretText)
			}
			return emitShares(cmd, info, shares, threshold, total, shareOutput{pdfPath: pdfPath})
		},
	}

	f := cmd.Flags()
	f.IntVarP(&length, "length", "l", 32, "length of the generated secret (must be even and ≥16; 16→20 words, 32→33 words)")
	f.IntVarP(&threshold, "threshold", "n", 3, "shares required to recover (N)")
	f.IntVarP(&total, "shares", "m", 5, "total shares to produce (M)")
	f.StringVar(&charset, "charset", "ascii", "character set: "+strings.Join(secret.PresetNames(), ", ")+", or a literal set")
	f.StringVar(&passphrase, "passphrase", "", "optional passphrase (printable ASCII) protecting the secret")
	f.BoolVar(&askPass, "ask-passphrase", false, "prompt for the passphrase on the terminal (avoids argv/shell history)")
	f.StringVar(&pdfPath, "pdf", "", "write a single multi-page backup PDF to this path (e.g. backup.pdf)")
	f.BoolVar(&showSecret, "show-secret", true, "echo the generated secret (disable to only emit shares)")

	return cmd
}
