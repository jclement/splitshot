# splitshot — Claude Code Guidelines

splitshot is a single-binary Go CLI that generates cryptographically secure
secrets and splits them with Shamir's Secret Sharing (SLIP-0039). Any N of M
shares recover the secret; fewer reveal nothing. See [README.md](README.md) for
usage and [DESIGN.md](DESIGN.md) for architecture and the crypto internals.

## Golden rules

- **Correctness is the product.** The SLIP-0039 implementation in
  `internal/slip039` is a faithful port of the Trezor reference and is verified
  against the **official test vectors** (`testdata/slip39-vectors.json`, run by
  `vectors_test.go`). Never change crypto constants or algorithms without
  re-running the full vector suite. Prefer local, audited code over new crypto
  dependencies.
- **All crypto is stdlib + local.** `crypto/rand`, `crypto/pbkdf2`,
  `crypto/hmac`, `crypto/sha256`, `math/big`. No third-party crypto libraries.
- **CGO is off.** `CGO_ENABLED=0` always; single static binary. Assets (the
  wordlist) are embedded via `//go:embed`.
- **Secrets never get logged.** Don't print secrets except where the UX
  explicitly intends (the one-time echo). Randomness comes from an injectable
  `io.Reader` so tests can drive it — keep it that way.
- **The PDF is a blank template.** `internal/pdf` is handed only a word *count*,
  never the words. Do not pass secret material into the PDF layer.

## Workflow (mandatory)

Run after every change, not just at the end:

```bash
mise run fmt     # format
mise run lint    # go vet + staticcheck — must be zero warnings
mise run test    # go test -race -cover ./... — must pass, no skips
```

- Add tests for every feature and bugfix. Match existing table-driven style.
- Aim to keep the high coverage we have (secret/taglines 100%, slip039 ~97%,
  pdf ~99%, cli ~95%). Error paths are covered by injecting failing readers.
- Update [README.md](README.md) for any user-visible change (flags, commands,
  behavior) and [DESIGN.md](DESIGN.md) for any architectural change.

## Layout

```
cmd/splitshot/main.go   — entrypoint: wires crypto/rand + ldflags build info
internal/slip039/       — SLIP-0039 core (GF256, RS1024, Feistel, share, API)
internal/secret/        — secure secret generation (charsets, rejection sampling)
internal/pdf/           — blank backup-sheet rendering (go-pdf/fpdf)
internal/cli/           — Cobra commands, Lipgloss styling, TTY-aware I/O
internal/taglines/      — ~200 sarcastic taglines
testdata/               — official SLIP-0039 vectors
```

## Conventions

- Style: keep messages sarcastic but the behavior correct and the errors
  helpful. Top-of-file comments explain *why* each file exists; exported
  symbols are documented.
- Shares are **mnemonic-only** (a tool-local hex format was deliberately
  removed). `-n` = threshold (required), `-m` = total. Constraint `2 ≤ n ≤ m ≤ 16`.
- Output discipline: shares to stdout (bare when piped), everything else to
  stderr, so `splitshot gen ... > shares.txt` stays clean.

## Release

`mise run release` bumps the version, tags, and pushes; the tag triggers
GoReleaser (static binaries + cosign-signed checksums + Homebrew formula to
`jclement/homebrew-tap`). No container images. Requires the `HOMEBREW_TAP_TOKEN`
GitHub Actions secret.
