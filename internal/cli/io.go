// io.go holds the small I/O helpers shared by the commands: TTY detection,
// reading shares from an input stream, parsing a set of shares, and writing
// files with owner-only permissions (these files hold key material).
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jclement/splitshot/internal/slip039"
	"golang.org/x/term"
)

// randSource is the entropy source for generation and splitting. It is a
// package var so tests can substitute a deterministic reader; production uses
// crypto/rand via SetRandSource in main.
var randSource io.Reader

// SetRandSource sets the entropy source used by gen/split. Call once at startup.
func SetRandSource(r io.Reader) { randSource = r }

// interactiveOverride, when non-nil, forces isTerminal's result. It exists so
// tests can exercise both the interactive (styled) and piped (bare) rendering
// paths without a real PTY. Production never sets it.
var interactiveOverride *bool

// isTerminal reports whether w is an interactive terminal. A non-os.File writer
// (e.g. a test buffer) is treated as non-interactive.
func isTerminal(w io.Writer) bool {
	if interactiveOverride != nil {
		return *interactiveOverride
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// defaultTerminalWidth is assumed when the real width can't be measured (a
// non-TTY writer, or the forced-interactive test path).
const defaultTerminalWidth = 80

// terminalWidth returns the column width of w if it's a real terminal, else a
// sensible default. Used to lay the word grid out as wide as the terminal
// allows (fewer rows on wide terminals).
func terminalWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 {
			return width
		}
	}
	return defaultTerminalWidth
}

// readShareLines reads share strings from r, one per line. Blank lines, lines
// beginning with '#' (comments), and pure separator lines ("---") are skipped,
// so a lightly-annotated paste still parses.
func readShareLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	// Mnemonics can be long; give the scanner room beyond the default 64KB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Trim(line, "-") == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading shares: %w", err)
	}
	return lines, nil
}

// parseShares parses and de-duplicates a set of share mnemonics. Duplicates
// (e.g. the same share pasted twice) are collapsed so they don't trip the
// "unique share index" rule during recovery. Returns an error naming the first
// share that fails to parse.
func parseShares(lines []string) ([]slip039.Share, error) {
	seen := make(map[string]struct{}, len(lines))
	var shares []slip039.Share
	for i, line := range lines {
		s, err := slip039.ShareFromMnemonic(line)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i+1, err)
		}
		// Identity key: a share is the same regardless of its encoding.
		key := fmt.Sprintf("%d/%d/%d/%x", s.Identifier, s.GroupIndex, s.MemberIndex, s.Value)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		shares = append(shares, s)
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}
	return shares, nil
}

// writeSecureFile writes data to path with 0600 permissions — these files may
// contain key material and should not be world-readable.
func writeSecureFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// writePDFFile creates the parent directory if needed and writes the PDF with
// owner-only permissions.
func writePDFFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}
	return writeSecureFile(path, data)
}
