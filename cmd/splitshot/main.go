// Command splitshot generates cryptographically secure secrets and splits them
// into SLIP-0039 Shamir shares (and back). This file is the thin entrypoint:
// it wires the crypto/rand entropy source, injects build metadata, and runs
// the Cobra command tree defined in internal/cli.
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/jclement/splitshot/internal/cli"
)

// Build metadata, injected via -ldflags at release time. Defaults make a plain
// `go build` produce sensible "dev" output.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Production entropy comes from the OS CSPRNG. Tests in internal/cli
	// substitute a deterministic reader instead.
	cli.SetRandSource(rand.Reader)

	root := cli.NewRootCmd(cli.BuildInfo{Version: version, Commit: commit, Date: date})
	if err := root.Execute(); err != nil {
		// Cobra is configured with SilenceErrors; print our own clean message.
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
