# splitshot

Generate cryptographically secure secrets and split them into Shamir shares, so
that any **N of M** shares reconstruct the secret and any fewer reveal *nothing*.
Shares are emitted as [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
mnemonics, with optional printable PDF backup sheets for cold storage.

> Because trusting one piece of paper was getting too exciting.

Single static binary. No CGO. All crypto is local and verified against the
official SLIP-0039 test vectors.

## What it does

- **Generate** a secure random secret and split it in one step (`gen`).
- **Split** an existing secret (password, seed, key) into shares (`split`).
- **Combine** a sufficient subset of shares back into the secret (`combine`).
- **PDF** backup sheets: blank, fill-in-by-hand templates per share (`pdf`, or `--pdf`).

Threshold semantics: `-n` is the number of shares **required** to recover (N),
`-m` is the **total** number of shares produced (M). Constraint: `2 ≤ n ≤ m ≤ 16`.

## Install

### Homebrew

```bash
brew install jclement/tap/splitshot
```

### Binary

Download a release archive for your OS/arch from
[Releases](https://github.com/jclement/splitshot/releases) and put `splitshot` on
your `PATH`.

### From source

```bash
go install github.com/jclement/splitshot/cmd/splitshot@latest
```

## Quick start

```bash
# Generate a strong secret (32-char ASCII, ~210 bits), split 2-of-3, write PDFs.
splitshot gen -n 2 -m 3 --pdf ./backups

# Recover it: paste any 2 of the 3 shares, one per line, then Ctrl-D.
splitshot combine

# Split a secret you already have.
printf '%s' 'correct-horse-battery!!' | splitshot split -n 2 -m 3 > shares.txt

# Recover from a file of shares.
splitshot combine < shares.txt
```

Output discipline: **shares go to stdout** (bare, one per line — pipe them
straight into `combine`), while the secret, banners, and PDF notices go to
**stderr**. So `splitshot gen ... > shares.txt` captures only the shares.

## Commands

| Command | What it does |
|---------|--------------|
| `splitshot gen` | Generate a random secret and split it into N-of-M shares |
| `splitshot split` | Split an existing secret (stdin or `--secret-file`) |
| `splitshot combine` | Reconstruct a secret from share mnemonics on stdin |
| `splitshot pdf` | Render blank PDF backup sheets from shares on stdin |
| `splitshot version` | Print version and build info |

## Key flags

| Flag | Commands | Description | Default |
|------|----------|-------------|---------|
| `-n, --threshold` | gen, split | Shares required to recover (N) | — (required) |
| `-m, --shares` | gen, split | Total shares to produce (M) | — (required) |
| `-l, --length` | gen | Secret length (must be even and ≥16; 16→20-word shares, 32→33-word) | `32` |
| `--charset` | gen | `alphanumeric`, `alpha`, `digits`, `hex`, `safe`, `ascii`, or a literal set | `ascii` |
| `--passphrase` | gen, split, combine | Optional passphrase (printable ASCII) protecting the secret | `""` |
| `--pdf` | gen, split | Directory to write blank PDF backup sheets into | — |
| `--show-secret` | gen, split | Echo the secret once (gen defaults on, split off) | — |
| `-o, --out` | pdf | Output directory for sheets | `.` |

## Security notes

- **Entropy** comes from the OS CSPRNG (`crypto/rand`); secret characters are
  chosen with rejection sampling, so there is no modulo bias.
- A **single share reveals nothing** about the secret — that is the whole point.
  Store shares in separate locations.
- The optional **passphrase** is a second factor: with the wrong passphrase,
  shares recover a *different* (plausible) secret rather than failing — enabling
  deniable "decoy" secrets. There is no way to detect the right passphrase from
  the shares alone.
- The **PDF never contains the words.** It is a blank handwriting template; only
  the parameters (share number, threshold, Set ID) are printed.
- PDF files are written with `0600` permissions.
- Recover on a **trusted, offline machine**. The recovered secret is the crown
  jewels; treat the terminal and shell history accordingly.

## Development

| Command | What it does |
|---------|-------------|
| `mise install` | Install all tools (Go, goreleaser, staticcheck) |
| `mise run test` | Run all tests with the race detector and coverage |
| `mise run cover` | Write an HTML coverage report (`coverage.html`) |
| `mise run lint` | `go vet` + `staticcheck` (must be clean) |
| `mise run fmt` | Format all Go code |
| `mise run build` | Build `bin/splitshot` |
| `mise run release` | Bump version, tag, and push (triggers the release workflow) |
| `mise run dev:reset` | Remove local build/coverage artifacts |

See [DESIGN.md](DESIGN.md) for architecture and the SLIP-0039 implementation details.

## License

MIT. (C) 2026 Jeff Clement.
