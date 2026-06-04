// cli_test.go drives the full command tree through Cobra with injected
// in/out/err buffers and a real CSPRNG, asserting the gen→combine and
// split→combine round-trips plus every user-facing error and both the piped
// and interactive rendering paths.
package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testInfo = BuildInfo{Version: "v1.2.3", Commit: "abc1234", Date: "2026-06-03"}

func TestMain(m *testing.M) {
	SetRandSource(rand.Reader)
	os.Exit(m.Run())
}

// run executes the command tree with the given stdin and args, returning
// stdout, stderr, and the execution error.
func run(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCmd(testInfo)
	var out, errb strings.Builder
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.Execute()
	return out.String(), errb.String(), err
}

// secretFromStderr pulls the echoed secret (the indented line after the
// "Your secret" warning) out of stderr.
func secretFromStderr(t *testing.T, stderr string) string {
	t.Helper()
	lines := strings.Split(stderr, "\n")
	for i, ln := range lines {
		if strings.Contains(ln, "Your secret") && i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	t.Fatalf("no secret found in stderr:\n%s", stderr)
	return ""
}

// forceInteractive sets the TTY override for the duration of the test.
func forceInteractive(t *testing.T, v bool) {
	t.Helper()
	interactiveOverride = &v
	t.Cleanup(func() { interactiveOverride = nil })
}

// ---------------------------------------------------------------------------
// gen
// ---------------------------------------------------------------------------

func TestGenCombineRoundTrip(t *testing.T) {
	out, errb, err := run(t, "", "gen", "-l", "30", "-n", "2", "-m", "3")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	secret := secretFromStderr(t, errb)

	// Feed the produced shares straight back into combine.
	recovered, _, err := run(t, out, "combine")
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if recovered != secret {
		t.Fatalf("round-trip mismatch: got %q want %q", recovered, secret)
	}
}

func TestGenCharset(t *testing.T) {
	_, errb, err := run(t, "", "gen", "-l", "16", "-n", "2", "-m", "2", "--charset", "digits")
	if err != nil {
		t.Fatal(err)
	}
	secret := secretFromStderr(t, errb)
	for _, c := range secret {
		if c < '0' || c > '9' {
			t.Fatalf("expected only digits, got %q", secret)
		}
	}
}

func TestGenNoShowSecret(t *testing.T) {
	out, errb, err := run(t, "", "gen", "-n", "2", "-m", "3", "--show-secret=false")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errb, "Your secret") {
		t.Fatal("secret should not be echoed with --show-secret=false")
	}
	if len(strings.Fields(strings.Split(out, "\n")[0])) == 0 {
		t.Fatal("expected shares on stdout")
	}
}

func TestGenErrors(t *testing.T) {
	cases := [][]string{
		{"gen", "-l", "15", "-n", "2", "-m", "3"}, // odd length
		{"gen", "-l", "10", "-n", "2", "-m", "3"}, // too short
		{"gen", "-l", "30", "-n", "5", "-m", "3"}, // threshold > total
		{"gen", "-m", "3"},                        // missing threshold
		{"gen", "-n", "2"},                        // missing shares
		{"gen", "-n", "2", "-m", "3", "--charset", "x"},
	}
	for _, args := range cases {
		if _, _, err := run(t, "", args...); err == nil {
			t.Fatalf("expected error for args %v", args)
		}
	}
}

func TestGenWritesPDFs(t *testing.T) {
	dir := t.TempDir()
	_, _, err := run(t, "", "gen", "-n", "2", "-m", "3", "--pdf", dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("expected 3 PDFs, got %d", len(entries))
	}
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("PDF %s has perms %o, want 0600", e.Name(), info.Mode().Perm())
		}
	}
}

// ---------------------------------------------------------------------------
// split
// ---------------------------------------------------------------------------

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := "sixteen-byte-key" // exactly 16 bytes, even
	out, _, err := run(t, secret+"\n", "split", "-n", "2", "-m", "3")
	if err != nil {
		t.Fatal(err)
	}
	recovered, _, err := run(t, out, "combine")
	if err != nil {
		t.Fatal(err)
	}
	if recovered != secret {
		t.Fatalf("got %q want %q", recovered, secret)
	}
}

func TestSplitSecretFileAndShowSecret(t *testing.T) {
	secret := "another16bytekey"
	file := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errb, err := run(t, "", "split", "-n", "2", "-m", "2", "--secret-file", file, "--show-secret")
	if err != nil {
		t.Fatal(err)
	}
	if secretFromStderr(t, errb) != secret {
		t.Fatal("echoed secret mismatch")
	}
	recovered, _, err := run(t, out, "combine")
	if err != nil || recovered != secret {
		t.Fatalf("combine: %v %q", err, recovered)
	}
}

func TestSplitErrors(t *testing.T) {
	if _, _, err := run(t, "", "split", "-n", "2", "-m", "3"); err == nil {
		t.Fatal("expected empty-stdin error")
	}
	if _, _, err := run(t, "too short\n", "split", "-n", "2", "-m", "3"); err == nil {
		t.Fatal("expected too-short secret error")
	}
	if _, _, err := run(t, "x", "split", "-n", "2", "-m", "3", "--secret-file", "/nonexistent/file"); err == nil {
		t.Fatal("expected missing-file error")
	}
}

// ---------------------------------------------------------------------------
// combine
// ---------------------------------------------------------------------------

func TestCombineSkipsCommentsAndSeparators(t *testing.T) {
	secret := "sixteen-byte-key"
	out, _, _ := run(t, secret+"\n", "split", "-n", "2", "-m", "3")
	shares := strings.Split(strings.TrimSpace(out), "\n")

	annotated := "# my backup\n" + shares[0] + "\n---\n\n" + shares[1] + "\n"
	recovered, _, err := run(t, annotated, "combine")
	if err != nil || recovered != secret {
		t.Fatalf("combine annotated: %v %q", err, recovered)
	}
}

func TestCombineErrors(t *testing.T) {
	if _, _, err := run(t, "", "combine"); err == nil {
		t.Fatal("expected empty error")
	}
	if _, _, err := run(t, "definitely not a valid share line\n", "combine"); err == nil {
		t.Fatal("expected parse error")
	}
	// A single valid share is well-formed but insufficient: exercises the
	// Combine (not parse) error path.
	out, _, _ := run(t, "sixteen-byte-key", "split", "-n", "2", "-m", "3")
	oneShare := strings.Split(strings.TrimSpace(out), "\n")[0]
	if _, _, err := run(t, oneShare+"\n", "combine"); err == nil {
		t.Fatal("expected insufficient-shares error")
	}
}

// TestPDFDirCreationFails covers the mkdir-failure branch by pointing the
// output directory underneath a regular file.
func TestPDFDirCreationFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "iamafile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(file, "subdir") // can't mkdir under a file

	if _, _, err := run(t, "", "gen", "-n", "2", "-m", "3", "--pdf", badDir); err == nil {
		t.Fatal("expected gen --pdf mkdir error")
	}
	out, _, _ := run(t, "sixteen-byte-key", "split", "-n", "2", "-m", "2")
	if _, _, err := run(t, out, "pdf", "-o", badDir); err == nil {
		t.Fatal("expected pdf -o mkdir error")
	}
}

func TestCombineWrongPassphraseDiffers(t *testing.T) {
	secret := "sixteen-byte-key"
	out, _, _ := run(t, secret, "split", "-n", "2", "-m", "2", "--passphrase", "right")
	recovered, _, err := run(t, out, "combine", "--passphrase", "wrong")
	if err != nil {
		t.Fatalf("combine should not error on wrong passphrase: %v", err)
	}
	if recovered == secret {
		t.Fatal("wrong passphrase should not recover the original")
	}
}

// ---------------------------------------------------------------------------
// pdf, version, help
// ---------------------------------------------------------------------------

func TestPDFCommand(t *testing.T) {
	secret := "sixteen-byte-key"
	out, _, _ := run(t, secret, "split", "-n", "2", "-m", "3")
	dir := t.TempDir()
	_, _, err := run(t, out, "pdf", "-o", dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("expected 3 PDFs, got %d", len(entries))
	}
}

func TestPDFCommandErrors(t *testing.T) {
	if _, _, err := run(t, "garbage line\n", "pdf"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestVersion(t *testing.T) {
	out, _, err := run(t, "", "version")
	if err != nil || !strings.Contains(out, "v1.2.3") {
		t.Fatalf("version subcommand: %v %q", err, out)
	}
	out, _, err = run(t, "", "--version")
	if err != nil || !strings.Contains(out, "v1.2.3") {
		t.Fatalf("--version: %v %q", err, out)
	}
}

func TestRootHelp(t *testing.T) {
	out, _, err := run(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Typical use") {
		t.Fatalf("expected help text, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// Interactive (styled) rendering paths
// ---------------------------------------------------------------------------

func TestInteractiveRendering(t *testing.T) {
	// Capture bare shares first, while still in non-interactive mode.
	secret := "sixteen-byte-key"
	bareShares, _, _ := run(t, secret, "split", "-n", "2", "-m", "2")

	forceInteractive(t, true)

	out, _, err := run(t, "", "gen", "-n", "2", "-m", "3")
	if err != nil {
		t.Fatal(err)
	}
	// In interactive mode the secret and labels go to stdout.
	for _, want := range []string{"Your secret", "Shares", "Share 1 of 3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("interactive output missing %q:\n%s", want, out)
		}
	}

	// combine in interactive mode prints a styled "Recovered secret:" header.
	rec, _, err := run(t, bareShares, "combine")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec, "Recovered secret:") {
		t.Fatalf("expected styled recovery header, got %q", rec)
	}
}
