// combine.go implements `combine`: read shares from stdin (mnemonic or hex,
// one per line) and reconstruct the secret. This is the recovery path.
package cli

import (
	"fmt"

	"github.com/jclement/splitshot/internal/slip039"
	"github.com/spf13/cobra"
)

// newCombineCmd builds the `combine` subcommand.
func newCombineCmd() *cobra.Command {
	var (
		passphrase string
		askPass    bool
	)

	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Reconstruct a secret from shares supplied on stdin",
		Long: "Read shares from stdin — one SLIP-0039 mnemonic per line — and reconstruct the\n" +
			"original secret. Duplicates are ignored. Blank lines, comment lines (starting\n" +
			"with #) and separators (---) are skipped. The recovered secret is written to\n" +
			"stdout.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pass, err := resolvePassphrase(passphrase, askPass, false)
			if err != nil {
				return err
			}
			lines, err := readShareLines(cmd.InOrStdin())
			if err != nil {
				return err
			}
			shares, err := parseShares(lines)
			if err != nil {
				return err
			}
			secret, err := slip039.Combine(shares, pass)
			if err != nil {
				return err
			}
			emitRecoveredSecret(cmd, secret)
			return nil
		},
	}

	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used when the secret was split")
	cmd.Flags().BoolVar(&askPass, "ask-passphrase", false, "prompt for the passphrase on the terminal (avoids argv/shell history)")
	return cmd
}

// emitRecoveredSecret writes the secret to stdout. Piped output gets the raw
// bytes with no trailing newline (so it round-trips exactly); interactive
// output gets a styled, newline-terminated display.
func emitRecoveredSecret(cmd *cobra.Command, secret []byte) {
	out := cmd.OutOrStdout()
	if !isTerminal(out) {
		out.Write(secret)
		return
	}
	t := newTheme(out)
	fmt.Fprintln(out, t.success.Render("Recovered secret:"))
	fmt.Fprintln(out, t.secretBox.Render(t.secret.Render(string(secret))))
}
