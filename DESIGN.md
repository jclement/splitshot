# splitshot — Design & Architecture

## Overview

splitshot generates cryptographically secure secrets and splits them with
Shamir's Secret Sharing so that any N of M shares reconstruct the secret and
fewer reveal nothing. It is a single static Go binary (CGO disabled) with no
runtime dependencies and no network access.

The sharing scheme is **SLIP-0039**, the SatoshiLabs standard purpose-built for
Shamir mnemonics. We implement it locally rather than depending on a third-party
crypto library, because correctness is the entire value proposition — and we
prove that correctness against the official SLIP-0039 test vectors. (SLIP-0039
uses its own 1024-word list, not the BIP39 2048-word list.)

## Architecture

splitshot is a Cobra command tree over a small set of focused packages. There is
no persistent state, no config file, and no daemon: input comes from flags and
stdin, output goes to stdout/stderr (and optional PDF files).

```
            ┌────────────────────────── cmd/splitshot ──────────────────────────┐
            │  main: inject crypto/rand + build info, run the Cobra command tree │
            └───────────────────────────────┬───────────────────────────────────┘
                                             │
                 ┌───────────────────────────┴───────────────────────────┐
                 │                      internal/cli                       │
                 │  gen · split · combine · pdf · version  (+ styles, io)  │
                 └───┬───────────────┬───────────────┬───────────────┬─────┘
                     │               │               │               │
            internal/secret   internal/slip039   internal/pdf   internal/taglines
            (CSPRNG secrets)  (SLIP-0039 core)   (backup PDFs)   (sarcasm)
```

Data flow:

- `gen`: `secret.Generate` → bytes → `slip039.Split` → shares → render (+PDF).
- `split`: read stdin/file → `slip039.Split` → shares → render (+PDF).
- `combine`: read stdin → parse/dedupe shares → `slip039.Combine` → secret.
- `pdf`: read stdin → parse shares → `pdf.Render` per share.

## Project structure

```
cmd/splitshot/main.go        — entrypoint: wires crypto/rand + ldflags build info
internal/
  slip039/
    constants.go             — spec constants (verbatim from SLIP-0039)
    gf256.go                 — GF(2^8) arithmetic + Lagrange interpolation
    rs1024.go                — RS1024 checksum
    encrypt.go               — Feistel cipher (PBKDF2-HMAC-SHA256 round function)
    digest.go                — share-integrity digest (truncated HMAC)
    share.go                 — Share type; mnemonic encode/decode
    wordlist.go / .txt       — embedded 1024-word list
    slip039.go               — public Split / Combine + raw Shamir split/recover
    vectors_test.go          — official SLIP-0039 vectors
  secret/generate.go         — crypto/rand secret generation, charsets, rejection sampling
  pdf/pdf.go                 — blank per-share backup sheet (go-pdf/fpdf, core fonts)
  cli/                       — Cobra commands, Lipgloss styles, TTY-aware I/O
  taglines/taglines.go       — ~200 taglines
testdata/slip39-vectors.json — official vectors, run in full by the test suite
```

## Key design decisions

1. **SLIP-0039, implemented locally.** The reference Trezor implementation is
   small and well-specified, and the spec ships exhaustive test vectors. We port
   it faithfully (constants copied verbatim, GF(256) tables computed from the
   field generator) and run all 45 official vectors in CI. This beats trusting an
   unaudited dependency for the one thing that must be exactly right.

2. **Threshold semantics: `-n` = required, `-m` = total.** Matches the backup
   sheet wording ("#X of M, N required"). Enforced `2 ≤ n ≤ m ≤ 16`; a 1-of-m
   "split" is rejected because it protects nothing.

3. **Self-describing shares.** SLIP-0039 shares embed their identifier, index,
   and member threshold, so `combine` never needs `-n`/`-m` told to it — it reads
   shares from stdin and figures out what it has. Extra shares are tolerated
   (a minimal subset is used); duplicate shares (e.g. pasted twice) are
   de-duplicated by logical identity before recovery.

4. **One encoding: the SLIP-0039 mnemonic.** The only share encoding is the
   canonical RS1024-checksummed word list — interoperable with other SLIP-0039
   tools, and the most error-resistant form for handwriting and re-typing. An
   earlier tool-local hex framing was removed: a second, non-interoperable
   encoding was a footgun with no real benefit.

5. **CSPRNG + rejection sampling.** All randomness is read from an injectable
   `io.Reader` (`crypto/rand.Reader` in production, deterministic readers in
   tests so the error paths are reachable). Character selection uses rejection
   sampling to eliminate modulo bias.

6. **The PDF is a blank template.** The renderer is given only a word *count*,
   never the words — so a backup sheet cannot leak the secret even by accident.
   It prints the share number, the threshold, a Set ID (the SLIP-0039 identifier,
   so sheets of one set are matchable), recovery instructions, and numbered empty
   boxes to handwrite into. Core PDF fonts (Helvetica/Courier) keep the binary
   free of embedded TTFs.

7. **TTY-aware output.** Lipgloss renderers are bound to the actual output
   writer, so a piped run emits plain, color-free, label-free shares on stdout
   (scriptable; feeds straight into `combine`) while an interactive terminal gets
   the styled report. The secret and all chrome go to stderr when piped.

## Crypto details

- **Field:** GF(2^8) modulo the Rijndael polynomial `x^8+x^4+x^3+x+1` (`0x11b`);
  log/exp tables are computed at init from the field generator.
- **Sharing:** the *encrypted* master secret is split. Reserved points `f(255)`
  (the secret) and `f(254)` (a truncated-HMAC digest) let recovery detect wrong
  or corrupt shares before returning anything.
- **Encryption:** a 4-round Feistel network whose round function is
  PBKDF2-HMAC-SHA256 (`10000 << e` iterations total over 4 rounds; `e=1` by
  default). The passphrase keys this layer. A wrong passphrase yields a different
  valid-looking secret, never an error — by design (decoy/deniability).
- **Checksum:** RS1024 Reed-Solomon over the mnemonic words, with the
  `"shamir_extendable"` customization string (we generate extendable shares).
- **Master-secret constraints:** at least 128 bits and an even number of bytes,
  per the spec. `gen` defaults to 30 bytes; odd/short inputs are rejected.

## Testing strategy

- **slip039:** all 45 official vectors (valid → recover expected secret; invalid
  → rejected), plus round-trips across many (threshold, total, length) shapes,
  mnemonic encode/decode, GF(256)/RS1024 unit checks, encrypt/decrypt round-trips,
  and every reachable error path. Randomness failures are injected via a failing
  reader. ~97% statement coverage (the remainder is unreachable defensive guards).
- **secret:** 100% — length/charset correctness, dedupe, rejection sampling, and
  RNG-failure branches via an erroring reader.
- **pdf:** ~99% — output is a valid PDF (`%PDF`…`%%EOF`), correct per-share count,
  invalid sheets rejected.
- **cli:** ~95% — gen→combine and split→combine round-trips, charset selection,
  comment/separator skipping, passphrase behavior, both piped and interactive
  rendering (via a test-only TTY override), and the user-facing error paths.
- All tests run under `-race`. `go vet` and `staticcheck` must be clean.

## Deployment

GoReleaser builds static binaries (`CGO_ENABLED=0`) for linux/darwin/windows ×
amd64/arm64 on every `v*` tag, signs checksums with keyless cosign, and pushes a
Homebrew formula to `jclement/homebrew-tap`. `mise run release` bumps the version
and pushes the tag that triggers it. (No container images are published — this is
a local CLI tool.)

## Known limitations & future work

- **Memory zeroing.** Go's GC and value copies mean secret bytes cannot be
  reliably wiped from memory. We avoid logging secrets and minimize copies, but
  this is a fundamental limitation of the runtime — recover on a trusted machine.
- **Single-group only on generation.** `Split` always produces one group;
  `Combine` understands the full SLIP-0039 group model (so it can recover
  externally-produced multi-group shares), but splitting into multiple groups is
  not exposed.
- **GoReleaser deprecation.** `brews` is valid today but flagged for eventual
  replacement by `homebrew_casks`; migrate when that stabilizes.
