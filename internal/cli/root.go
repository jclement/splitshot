// Package cli wires up the splitshot command tree (gen, split, combine, pdf,
// version) on top of Cobra. Commands read entropy from a package-level source
// (set via SetRandSource) and write through Cobra's in/out/err streams, so the
// whole surface is testable with injected buffers.
package cli

import (
	"fmt"
	"runtime"

	"github.com/jclement/splitshot/internal/taglines"
	"github.com/spf13/cobra"
)

// BuildInfo carries the version metadata injected at build time via ldflags.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// NewRootCmd builds the root command and attaches every subcommand.
func NewRootCmd(info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:   "splitshot",
		Short: "Generate secure secrets and split them with Shamir secret sharing",
		Long: "splitshot — generate cryptographically secure secrets and split them into\n" +
			"SLIP-0039 mnemonic (or hex) shares, so that any N of M shares recover the\n" +
			"secret and any fewer reveal nothing.\n\n" +
			"  " + taglines.Pick(int(info.versionSeed())) + "\n\n" +
			"Typical use:\n" +
			"  splitshot gen -n 2 -m 3            generate a secret, split 2-of-3\n" +
			"  splitshot split -n 2 -m 3          split an existing secret from stdin\n" +
			"  splitshot combine                  recover a secret from shares on stdin\n" +
			"  splitshot pdf -o ./out             make printable backup sheets from shares",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       versionString(info),
		// No Run: with no subcommand, Cobra prints help.
	}
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(
		newGenCmd(info),
		newSplitCmd(info),
		newCombineCmd(),
		newPDFCmd(info),
		newVersionCmd(info),
	)
	return root
}

// versionSeed derives a stable index into the tagline list from the version,
// so the help banner's tagline is consistent within a build but varies across
// releases.
func (info BuildInfo) versionSeed() uint32 {
	var sum uint32
	for _, c := range info.Version {
		sum = sum*31 + uint32(c)
	}
	return sum
}

// versionString renders the one-line version (used by --version).
func versionString(info BuildInfo) string {
	return fmt.Sprintf("splitshot %s (%s, %s) %s/%s",
		info.Version, info.Commit, info.Date, runtime.GOOS, runtime.GOARCH)
}
