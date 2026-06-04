// split.go implements `split`: take an existing secret (from stdin or a file)
// and split it into N-of-M shares. Use this when the secret already exists —
// an existing master password, a wallet seed, a long-lived API key.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jclement/splitshot/internal/slip039"
	"github.com/spf13/cobra"
)

// newSplitCmd builds the `split` subcommand.
func newSplitCmd(info BuildInfo) *cobra.Command {
	var (
		threshold  int
		total      int
		passphrase string
		askPass    bool
		pdfPath    string
		secretFile string
		showSecret bool
	)

	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split an existing secret (from stdin or --secret-file) into N-of-M shares",
		Long: "Split a secret you already have into M shares, any N of which reconstruct it.\n" +
			"The secret is read from stdin by default, or from --secret-file. A single\n" +
			"trailing newline is stripped. The secret must be at least 16 bytes and an even\n" +
			"number of bytes (a SLIP-0039 requirement).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pass, err := resolvePassphrase(passphrase, askPass, true)
			if err != nil {
				return err
			}
			secretBytes, err := readSecret(cmd, secretFile)
			if err != nil {
				return err
			}
			shares, err := slip039.Split(secretBytes, threshold, total, pass, randSource)
			if err != nil {
				return err
			}
			if showSecret {
				emitSecret(cmd, string(secretBytes))
			}
			return emitShares(cmd, info, shares, threshold, total, shareOutput{pdfPath: pdfPath})
		},
	}

	f := cmd.Flags()
	f.IntVarP(&threshold, "threshold", "n", 3, "shares required to recover (N)")
	f.IntVarP(&total, "shares", "m", 5, "total shares to produce (M)")
	f.StringVar(&passphrase, "passphrase", "", "optional passphrase (printable ASCII) protecting the secret")
	f.BoolVar(&askPass, "ask-passphrase", false, "prompt for the passphrase on the terminal (avoids argv/shell history)")
	f.StringVar(&pdfPath, "pdf", "", "write a single multi-page backup PDF to this path (e.g. backup.pdf)")
	f.StringVar(&secretFile, "secret-file", "", "read the secret from this file instead of stdin")
	f.BoolVar(&showSecret, "show-secret", false, "echo the secret back after reading it")

	return cmd
}

// readSecret reads the secret from secretFile, or from the command's stdin if
// no file is given. A single trailing newline (or CRLF) is stripped so that
// `echo "secret" | splitshot split` does the obvious thing.
func readSecret(cmd *cobra.Command, secretFile string) ([]byte, error) {
	var data []byte
	var err error
	if secretFile != "" {
		data, err = os.ReadFile(secretFile)
		if err != nil {
			return nil, fmt.Errorf("reading secret file: %w", err)
		}
	} else {
		data, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("reading secret from stdin: %w", err)
		}
	}
	data = []byte(strings.TrimSuffix(string(data), "\n"))
	data = []byte(strings.TrimSuffix(string(data), "\r"))
	if len(data) == 0 {
		return nil, fmt.Errorf("no secret provided (stdin was empty)")
	}
	return data, nil
}
