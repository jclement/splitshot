// version.go implements the `version` subcommand, which prints full build and
// runtime details (more than the one-line --version flag).
package cli

import (
	"fmt"
	"runtime"

	"github.com/jclement/splitshot/internal/taglines"
	"github.com/spf13/cobra"
)

// newVersionCmd builds the `version` subcommand.
func newVersionCmd(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			t := newTheme(out)
			fmt.Fprintln(out, t.title.Render("splitshot")+" "+info.Version)
			fmt.Fprintln(out, t.tagline.Render(taglines.Pick(int(info.versionSeed()))))
			fmt.Fprintln(out)
			fmt.Fprintf(out, "  commit:   %s\n", info.Commit)
			fmt.Fprintf(out, "  built:    %s\n", info.Date)
			fmt.Fprintf(out, "  go:       %s\n", runtime.Version())
			fmt.Fprintf(out, "  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
