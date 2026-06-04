# Security & Correctness Audit — `splitshot`

## Executive Summary

`splitshot` is an offline Go CLI that generates high-entropy secrets and splits them into SLIP-0039 Shamir shares, with a from-scratch local port of the Trezor `python-shamir-mnemonic` reference. This audit found the cryptographic core to be **correct, conformant, and faithful to the reference**. All 45 official SLIP-0039 test vectors pass, the GF(256) field arithmetic and Lagrange interpolation are verified bias-free and reference-exact, the RS1024 checksum (including the commonly mistyped final GEN-table entry) and the 1024-word wordlist are byte-identical to upstream, and the random secret generator uses provably unbiased rejection sampling over an injected `crypto/rand` source. **There are zero confirmed critical or high-severity findings.** The single most actionable issue is **medium**: passphrases can only be supplied via the `--passphrase` flag, exposing the documented "second factor" in process argv and shell history. The remaining confirmed findings are low/info — defensive-coding nits, faithful-to-reference non-constant-time comparisons in an offline context, API-contract gaps behind unreachable guards, and test-coverage/labeling improvements. **Overall verdict: the tool is sound and safe for its stated purpose; address the passphrase-input issue and the handful of low-severity hardening items.**

> This is an internal, partly-automated adversarial review. It is **not** a substitute for a professional human cryptographic audit before high-value production use.

---

## Scope & Methodology

The review was conducted as a multi-agent adversarial process across seven dimensions, with every candidate finding independently verified from **two lenses** — an *exploitability* lens (could this cause a wrong, lost, or leaked secret, or weakened entropy in the shipping offline CLI?) and a *spec-correctness* lens (does it match SLIP-0039 and the Trezor reference byte-for-byte?). A finding was promoted to **confirmed** only if it survived both perspectives.

Dimensions reviewed:

1. **Secret generation & randomness** — `internal/secret/generate.go`
2. **Shamir secret sharing & GF(256)** — `gf256.go`, `slip039.go`, `digest.go`
3. **SLIP-0039 mnemonic encoding & RS1024 checksum** — `share.go`, `rs1024.go`, `wordlist.go/.txt`
4. **Feistel cipher, PBKDF2, passphrase handling** — `encrypt.go`, `constants.go`
5. **Conformance to spec & test-vector coverage** — `testdata/slip39-vectors.json`, `vectors_test.go`
6. **Application security & secret hygiene** — `internal/cli/*`, `internal/pdf/*`
7. **Unit-test completeness & coverage gaps** — all `*_test.go`

Techniques used: line-by-line diffing against the upstream Trezor `python-shamir-mnemonic` master source; exhaustive verification of GF(256) tables and rejection-sampling math; runtime execution of the official vectors and the full test suite; coverage profiling (`go test -covermode=atomic`); targeted runtime probes (subset recovery, corrupt-share rejection, RNG-failure injection, multi-group stress testing for map-iteration determinism); and CLI behavioral checks (`ps`/argv exposure, file permissions, stdout/stderr routing). No files were modified — this was a read-only review.

---

## Findings Summary

| # | Severity | Dimension | Finding |
|---|----------|-----------|---------|
| 1 | **Medium** | App-sec | Passphrase only accepted via `--passphrase` flag (argv / shell-history exposure) |
| 2 | Low | Secret gen | `Generate` enforces only `length>=1`, not the even/`>=16` minimum its flag advertises |
| 3 | Low | Secret gen | `uniformIndex` silently infinite-loops if ever called with `n>256` (latent, unreachable) |
| 4 | Low | Shamir | Digest comparison `equalBytes` is not constant-time (matches reference) |
| 5 | Low | Cipher | `Combine()` validates passphrase ASCII; reference `combine_mnemonics` does not |
| 6 | Low | Tests | Odd-length-secret validation branch in `Split` is untested (mislabeled test case) |
| 7 | Low | Tests | No statistical/distribution test for `Generate`/`uniformIndex` uniformity |
| 8 | Info | Secret gen | Generated secret lives in immutable Go strings; never zeroized (documented) |
| 9 | Info | Shamir | Doc comment on PBKDF2 iteration count is ambiguous (`20000` is the total, not per-round) |
| 10 | Info | Shamir | `recoverEMS` relaxes the reference's exact-count requirement (intentional, safe) |
| 11 | Info | Mnemonic | `Decode` does not range-check exponent/threshold/index (matches reference) |
| 12 | Info | Cipher | Passphrase ASCII validation operates on UTF-8 bytes (spec-correct) |
| 13 | Info | Conformance | `Split` hardcoded `extendable=true`, `iterationExponent=1`; legacy encode paths lack first-party round-trip |
| 14 | Info | Conformance | `splitshot` cannot produce multi-group shares; multi-group recovery is vector-only |
| 15 | Info | Tests | PBKDF2 error returns are unreachable defensive guards (uncovered) |
| 16 | Info | Tests | `interpolate` error-propagation branches uncovered via public API |
| 17 | Info | Tests | Non-default iteration exponent decode covered only indirectly (via vectors) |
| 18 | Info | Tests | `wordlist` init-panic and `isTerminal`/`terminalWidth` helpers untested (non-crypto) |

Confirmed: **0 critical, 0 high, 1 medium, 6 low, 11 info.**

---

## Detailed Findings

### 1. [Medium] Passphrase only accepted via `--passphrase`, exposing it in argv and shell history

**Location:** `internal/cli/gen.go:54`, `internal/cli/split.go:54`, `internal/cli/combine.go:42`, `internal/cli/pdf.go:67`

**Description.** Every command ingests the passphrase exclusively through a Cobra `--passphrase` string flag. There is no interactive prompt, stdin path, or environment-variable fallback anywhere in the tree (a grep for `ReadPassword`/`getpass`/`prompt` returns no passphrase-input path; `golang.org/x/term` is imported but used only for `IsTerminal`/`GetSize`). A value passed as `splitshot combine --passphrase hunter2` is therefore visible to any local user via `ps aux` / `/proc/<pid>/cmdline` for the process lifetime, and is persisted in shell history (`~/.zsh_history`, `~/.bash_history`) indefinitely.

This specifically undercuts the documented threat model: the README markets the passphrase as a "real second factor" and a coercion-resistant decoy (README.md:122-125, 292-295). If the passphrase lands in shell history while the shares are stored elsewhere, an attacker who later reads the history file plus obtains the shares has *both* factors, and the plausible-deniability property is weakened. The secret bytes themselves are *not* exposed on argv (they are read from stdin/file), so this is scoped precisely to the passphrase.

**Evidence.** Only passphrase ingestion is `f.StringVar(&passphrase, "passphrase", ...)` in all four commands. The Trezor `python-shamir-mnemonic` CLI prompts interactively instead of taking the passphrase on argv (CWE-214 / CWE-526 class).

**Why medium, not higher.** This is an offline, single-user CLI; the passphrase is optional (most users won't set one) and the process is short-lived, so the process-list angle is weak. The persistent shell-history disclosure is the real bite, but it is gated on optional usage plus an attacker with later history-file access. No wrong/lost-secret or entropy outcome results — only confidentiality erosion of an optional second factor.

**Recommendation.** Add a secure-input path: when `--passphrase` is omitted and stdin is a TTY, prompt via `golang.org/x/term`'s `ReadPassword` (already a dependency). Support a dedicated fd or env-var fallback for scripting. At minimum, document the argv/shell-history exposure in the README and recommend the interactive prompt.

---

### 2. [Low] `secret.Generate` enforces only `length>=1`, not the even/`>=16` minimum advertised by its flag

**Location:** `internal/secret/generate.go:84-85`; flag help `internal/cli/gen.go:50`

**Description.** `Generate`'s only length guard is `if length < 1`. The `--length` flag help advertises "must be even and ≥16." The even/`≥16` floor actually lives downstream in `slip039.Split` (`slip039.go:46-47` rejects `<16` bytes; `:49-51` rejects odd lengths), which the sole production caller (`gen.go:34→38`) always routes through. So no weak short/odd secret can ever be produced end-to-end. The gap is an API-contract one: `Generate` is exported with a weaker guarantee than the CLI advertises. (Note: `Generate`'s own doc comment makes no even/`≥16` promise — the contract lives in the flag help, so the precise mismatch is "flag help vs enforcement location.")

**Evidence.** `gen -l 2 --charset digits` → `error: secret must be at least 16 bytes (got 2)`; `gen -l 17` → `error: secret length in bytes must be even (got 17)` — both errors originate from `Split`, not `Generate`. `Generate(2, "AB", rand)` alone returns a 2-char secret with no error.

**Recommendation.** Hoist the even/`≥16` validation into `Generate` (or document that callers must enforce policy), and optionally validate the flag in `gen.go` for a clearer message than the downstream `Split` error.

---

### 3. [Low] `uniformIndex` silently infinite-loops if ever called with `n>256` (latent, not currently reachable)

**Location:** `internal/secret/generate.go:105-118`

**Description.** `uniformIndex` documents its contract as `n ∈ [1,256]` but does not enforce it. For `n>256`, `256%n == 256`, so `limit = 256-256 = 0`, and the accept test `int(buf[0]) < 0` can never hold — the function loops forever, endlessly draining the RNG with no error. This is **not reachable**: `dedupe` keys on `map[byte]`, so `ResolveCharset` can return at most 256 distinct bytes, and `uniformIndex` is unexported and called only from `Generate` with a deduped set (a 300-rune UTF-8 charset collapses to ≤256 bytes). A latent robustness gap, not a live bug.

**Evidence.** Arithmetic verified for `n ∈ {257,300,512}`: all give `limit=0`. The legitimate boundary `n=256` is fine (`256%256=0`, `limit=256`, no bias). Only non-test caller is `generate.go:94`, passing `len(set) ≤ 256`.

**Recommendation.** Add a guard at the top of `uniformIndex`: `if n < 1 || n > 256 { return 0, fmt.Errorf(...) }`. Cheap insurance turning a silent hang into a clear error if the function is ever reused.

---

### 4. [Low] Integrity-digest comparison is not constant-time

**Location:** `internal/slip039/slip039.go:296-306` (`equalBytes`), used at `slip039.go:253`

**Description.** `recoverSecret` verifies the integrity digest with `equalBytes`, which short-circuits on the first differing byte rather than using `crypto/subtle.ConstantTimeCompare` / `hmac.Equal`. This faithfully mirrors the Trezor reference, which uses a plain `digest != _create_digest(...)` (Python bytes inequality is likewise non-constant-time) — so it is **not a regression or a spec deviation**.

The practical risk is negligible: the comparison runs only locally during recovery, only *after* a full threshold of shares has been interpolated (at which point the attacker already holds everything needed to reconstruct the secret), and the 4-byte digest is a truncated HMAC keyed by per-split fresh randomness — both operands derive from shares the operator supplied, not a secret-vs-attacker-input match. `splitshot` is an offline CLI with no remote/repeatable timing oracle.

**Recommendation.** Optional defense-in-depth / intent-signaling: switch to `crypto/subtle.ConstantTimeCompare` or `hmac.Equal`. No behavioral or conformance change. (This same observation surfaced under multiple dimensions — see findings 4 here and the equivalent info-level notes — and is consistently a documented non-issue in the offline threat model.)

---

### 5. [Low] `Combine()` validates passphrase ASCII; the reference `combine_mnemonics` does not

**Location:** `internal/slip039/slip039.go:88-91` (`validatePassphrase` call in `Combine`)

**Description.** `validatePassphrase` (printable ASCII 32–126) correctly matches the reference and is correctly enforced in `Split` (mirroring `generate_mnemonics`). However the Go `Combine` *also* calls it, whereas the reference `combine_mnemonics` performs **no** passphrase validation on recovery — it passes raw bytes straight to `decrypt`. This makes splitshot's recovery path stricter than the reference. It is harmless for secrets created by this tool (Split already rejects non-ASCII passphrases, so no in-tool share set can require one). The only observable divergence is interop: recovering shares produced by another conforming tool that permitted a non-printable-ASCII passphrase would error instead of decrypting.

**Evidence.** Reference `combine_mnemonics` (shamir.py:459-477) ends with `return encrypted_master_secret.decrypt(passphrase)` and has no `all(32<=c<=126)` check; that check exists only in `generate_mnemonics` (line 391). Go `Combine` (slip039.go:89) calls `validatePassphrase` before `recoverEMS`/`decrypt`.

**Recommendation.** Either drop `validatePassphrase` from `Combine` to match the reference (recovery should be maximally permissive), or document the intentional divergence. Low priority since the default tool never produces such a set.

---

### 6. [Low] Odd-length-secret validation branch in `Split` is untested (mislabeled test case)

**Location:** `internal/slip039/slip039.go:49-51`; test `internal/slip039/slip039_test.go:155`

**Description.** `Split` has two sequential guards: a "too short" check (`len < 16`, lines 46-48) and an "odd length" check (`len%2 != 0`, lines 49-51). `TestSplitValidation` includes a case named "secret odd length" using a 15-byte secret — but 15 < 16, so it is rejected by the *too-short* guard and never reaches the odd-length guard. The odd-length branch is therefore **uncovered** (confirmed `count 0` in the coverage profile), and the named test gives false assurance. The guard logic itself is correct (a 17-byte probe returns the proper even-length error); this is a test-coverage/labeling defect only.

**Evidence.** Coverage profile: `slip039.go:49.24,51.3 1 0` (uncovered). A temporary probe (since removed): `Split(15 bytes)` → "secret must be at least 16 bytes (got 15)"; `Split(17 bytes)` → "secret length in bytes must be even (got 17)".

**Recommendation.** Add a `Split` validation case with an odd length ≥16 (e.g. 17 bytes) and assert the error mentions even length. Optionally relabel the 15-byte case to "secret too short (odd)".

---

### 7. [Low] No statistical/distribution test for `Generate`/`uniformIndex` output uniformity

**Location:** `internal/secret/generate.go:83-118`; `generate_test.go`

**Description.** Existing tests verify output length, alphabet membership, and the rejection boundary on crafted inputs, but none draws many samples to check the empirical distribution is roughly uniform, nor that the byte→index mapping covers all indices. The production code is **correct** (`limit = 256-(256%n)`, reject `>= limit`, then `%n`), and the most obvious bias regression (dropping rejection) *would* be caught by the existing crafted-byte test. But a subtler off-by-one in `limit` could pass all current tests because membership and length would still hold.

**Evidence.** `generate_test.go` asserts only membership/length/boundary; crafted-byte tests use `n=62` and `n=256` only, not a mid-range `n` (e.g. `n=10`, `limit=250`) where bias would manifest.

**Recommendation.** Add a large-sample test (e.g. 100k draws from `digits`) asserting every symbol appears within a loose tolerance / chi-square threshold, and a `uniformIndex` test at `n=10` confirming bytes 250–255 are rejected and 0–249 map across all 10 indices.

---

### Info-level findings (verified accurate, no action required)

- **8. Secret not zeroized** (`generate.go:92-100`, `gen.go:34-45`). The secret is built as `[]byte` then returned as an immutable Go string; the GC may copy it, so reliable wiping is impossible without an end-to-end `[]byte` rewrite. Standard for a one-shot CLI; the secret is deliberately printed anyway. This limitation is honestly documented in `DESIGN.md:157-159`. No action required for the stated threat model.

- **9. PBKDF2 iteration-count comment is ambiguous** (`slip039.go:13-15`). The comment says "10000<<1 = 20000 PBKDF2 iterations." 20000 is the genuine *total* across the 4 Feistel rounds (each round does `(10000<<1)/4 = 5000`, matching `encrypt.go:21` and the reference). The number is not wrong; the comment merely omits the per-round breakdown. (One verifier judged this not even a defect since 20000 is accurate as a total.) Optional: clarify to "5000/round × 4 rounds."

- **10. `recoverEMS` relaxes the reference's exact-count requirement** (`slip039.go:115-175`). The Go port deliberately tolerates *extra* valid shares (truncating each group to `memberThreshold` and stopping at `group_threshold` groups) where the reference rejects them. Verified safe: all retained shares must pass `common()`/`group()` parameter-equality checks; duplicate member indices are still rejected by `interpolate`; and the HMAC digest is independently verified, so a wrong-but-parameter-matching share is caught. Official vectors 30/31/33/34/35 (the malformed cases the reference rejects) still pass — the relaxation only additionally accepts well-formed supersets of a valid quorum.

- **11. `Decode` does not range-check exponent/threshold/index** (`share.go:124-150`). `ShareFromMnemonic` performs exactly one structural check (`groupCount < groupThreshold`), byte-for-byte matching the reference `from_mnemonic`. Correctness is enforced downstream (digest verification, parameter consistency). Member/group fields are 4-bit, so values ≥16 are structurally unrepresentable — the suggested defense-in-depth bound is moot.

- **12. Passphrase ASCII validation operates on UTF-8 bytes** (`slip039.go:264-271`). Multibyte Unicode is rejected with the printable-ASCII error — exactly the SLIP-0039 spec behavior, matching the reference. Validation and encryption use the same `[]byte(passphrase)` view, so there is no validate/use mismatch, truncation, or normalization bug. Spec-correct; optionally note the ASCII-only constraint in CLI help.

- **13. `Split` hardcoded to `extendable=true`, `iterationExponent=1`** (`slip039.go:16,57,72`). The non-extendable salt path and exponent>1 are exercised only on the *decode* side (via official legacy/exponent vectors), never as a first-party `Split→Combine` round-trip. A deliberate, defensible product decision (always modern extendable backups). Note: `TestEncryptDecryptRoundTrip` already round-trips the `extendable=false` *encode* path; the only genuine gap is `iterationExponent>1` in a first-party encode test.

- **14. `splitshot` cannot produce multi-group shares** (`slip039.go:67-80` vs `:115-175`). `Split` only emits `GroupIndex:0, GroupThreshold:1, GroupCount:1`. The full multi-group model in `recoverEMS` is correct but validated exclusively by official vectors. A stress test (multi-group `Combine` run hundreds of times across fresh process seeds) confirmed the Go-random map-iteration subset selection is deterministic and order-independent — any valid threshold subset recovers the identical secret via Lagrange interpolation. Recommend documenting "Split is single-group by design; multi-group is decode-only."

- **15. PBKDF2 error returns are unreachable defensive guards** (`encrypt.go:23-25,71-73,91-93`). `pbkdf2.Key` with SHA-256 and a small `keyLength` (≤64 bytes) cannot error in default builds, so these branches are uncovered. Defensible defensive coding. (One caveat surfaced: under `GODEBUG=fips140=only`, a <14-byte key could trigger the FIPS guard — not applicable to splitshot's offline non-FIPS usage.)

- **16. `interpolate` error-propagation branches uncovered via public API** (`slip039.go:58-60,171-173,228-230,248-250`). Callers pre-validate (Split rejects odd lengths before `encryptMasterSecret`; `recoverEMS` builds equal-length, unique-x raw shares), so these propagation paths require malformed internal state. `interpolate` itself is directly tested via `TestInterpolateErrors`. Optional white-box test for the propagation.

- **17. Non-default iteration exponent covered only indirectly** (`encrypt.go:61-97`). The exponent-dependence of `(baseIterationCount<<e)/roundCount` is exercised only by official vectors #7/#26 through `Combine`. A formula bug would still round-trip self-consistently within splitshot, so the vectors (which decode reference-produced mnemonics) are what actually pin it. Optional direct e=0/e=2 unit round-trip.

- **18. `wordlist` init-panic and terminal helpers untested** (`wordlist.go:26`; `io.go` `isTerminal` 83.3%, `terminalWidth` 50%). The 1024-word integrity guard cannot fire without corrupting the build asset (wordlist content is implicitly validated by every vector round-trip); terminal helpers only affect rendering. Non-crypto. Worth a cheap test asserting `len(wordList)==1024` *and* uniqueness to lock the embedded asset against accidental edits (init currently checks only the count).

---

## Refuted / Not-an-Issue

No candidate findings were promoted then refuted as material defects. During verification, several items were explicitly checked and **cleared**:

- **Modulo bias in secret generation** — `uniformIndex` rejection sampling was exhaustively verified bias-free for every `n ∈ [1,256]`.
- **GF(256) table or arithmetic errors** — `g=3` confirmed a full-period generator; table multiplication matches direct GF(256) multiply (poly `0x11b`) for all 255×255 nonzero pairs.
- **RS1024 GEN-table typo** — the frequently-mistyped final entry `0x3F3F120` is byte-exact (verified programmatically).
- **Wordlist tampering / wrong order** — byte-identical to the official Trezor list (1024 unique, sorted words).
- **Leading-zero secret corruption** — `bigIntToFixedBytes` left-padding correctly round-trips all-`0x00` / leading-`0x00` and all-`0xFF` secrets (verified by ad-hoc round-trip).
- **Reserved-index collision (254/255)** — structurally impossible: member indices are capped at 0–15.
- **Insecure RNG** — `math/rand` is never imported in non-test code; entropy is injected as `crypto/rand.Reader`.

Two info-level items (the PBKDF2 comment, #9, and one phrasing of the non-constant-time digest comparison) drew a "refuted" vote from one verifier on the grounds that the *defect framing* overstated a correct implementation; the underlying code in both cases is correct, which is why they remain info-level observations rather than defects.

---

## What Is Correct — Strengths

The three areas that must be flawless are all correct and conformance-anchored.

### Random secret generation — verified by unit tests (100% coverage)
- Entropy injected as an `io.Reader`, wired to `crypto/rand.Reader` in production (`cmd/splitshot/main.go:26`). No `math/rand` anywhere in non-test code.
- `uniformIndex` rejection sampling is **provably bias-free** for all `n ∈ [1,256]` (`limit = 256 - 256%n`, reject `>= limit`, then `%n`); exhaustively verified.
- A failing/short reader surfaces an error and never falls back to weak output (`io.ReadFull` → wrapped → propagated; `TestGenerateErrors`). No silent degradation.
- Charsets are deduplicated (`map[byte]`), capping `n` at 256 and preventing repeated-alphabet bias; `<2` distinct chars rejected.
- **Coverage: 100%** for the `secret` package, including the rejection branch and the no-reject `n=256` edge.

### Shamir splitting & GF(256) — verified by official vectors AND unit tests
- GF(256) exp/log tables and table-multiplication verified correct against direct field multiply for all nonzero pairs.
- `interpolate` is a faithful port of `_interpolate` (unique-x and equal-length checks, log-domain Lagrange, `share_val==0` skip, `%255` reduction with correct Go signed-modulo normalization).
- `splitSecret` reserves indices 254 (digest) / 255 (secret) correctly; member indices 0–15 can never collide.
- Digest = `HMAC-SHA256(key=randomData, msg=sharedSecret)[:4]`, verified before returning the secret — corrupt/wrong share sets never silently yield garbage (verified at runtime: single-byte corruption → "invalid digest of the shared secret").
- Runtime-verified threshold behavior: all C(5,3)=10 subsets recover; 2 shares fail; extra shares recover; RNG failures propagate as errors (never partial output).
- **All 45 official SLIP-0039 vectors pass; package coverage 97.1%.**

### SLIP-0039 mnemonic encoding & RS1024 — verified by official vectors AND unit tests
- RS1024 GEN table + `polymod` + create/verify are line-for-line identical to the reference (incl. the `0x3F3F120` final entry, checked via `TestAuditGENTable`).
- RS1024 detects 100% of single-word transcription errors — an exhaustive 33,759-mutation substitution test had 0 false accepts.
- `wordlist.txt` is byte-identical to the official Trezor list (1024 unique, sorted); `init()` panics if not exactly 1024 words.
- Bit-packing (ID/exp, 4-bit group/member fields, ±1 threshold offsets), customization strings (`shamir`/`shamir_extendable`), and `math/big` big-endian value↔word conversion (with leading-zero re-padding) all match `share.py`.
- **All 45 vectors pass** (15 valid recover + 30 invalid reject, including invalid-checksum, invalid-padding, insufficient-length, and modular-arithmetic detectors); none skipped.

### Cross-cutting strengths
- **Feistel/PBKDF2 cipher** byte-for-byte faithful: `(BASE_ITERATION_COUNT<<e)//ROUND_COUNT`, password `byte(i)||passphrase`, salt `getSalt||r`, correct inverse round order; wrong-passphrase yields a *different* valid-looking secret (plausible-deniability invariant verified).
- **Constants** match the reference verbatim (`BASE_ITERATION_COUNT=10000`, `ROUND_COUNT=4`, `SECRET_INDEX=255`, `DIGEST_INDEX=254`, `DIGEST_LENGTH_BYTES=4`, `MAX_SHARE_COUNT=16`, `ID_LENGTH_BITS=15`).
- **Supply chain:** all crypto is Go stdlib (`crypto/rand`, `crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`, `math/big`); third-party deps are confined to CLI/PDF/terminal and never touch key material. `go mod verify` clean; `go vet` and `staticcheck` clean.
- **Output hygiene:** shares → stdout, secret + chrome → stderr when piped (verified: `splitshot gen >shares.txt` leaves only mnemonics in the file). Files written `0600`, directories `0700`. No secret/share value is interpolated into any log or error message; no logging framework is wired in. No temp files.

---

## Test-Vector & Coverage Status

- **Official SLIP-0039 vectors:** 45/45 pass via `TestOfficialVectors` (15 valid + 30 invalid; none skipped). The current canonical Trezor set including extendable-backup additions (42–45) and the modular-arithmetic detector (41) is present; the loader guards against truncation (`len(vectors) < 40 → Fatal`).
- **Coverage (statement, `-covermode=atomic`):** `internal/secret` **100%**, `internal/slip039` **97.1%**, `internal/pdf` 97.7%, `internal/cli` 94.6%; **~96% overall.** The few uncovered crypto lines are predominantly unreachable defensive error returns (PBKDF2 cannot fail for SHA-256 with short keys) and the wordlist integrity-panic branch.

---

## Prioritized Recommendations

1. **(Medium)** Add a secure passphrase-input path — TTY prompt via `golang.org/x/term.ReadPassword` when `--passphrase` is omitted, plus an fd/env fallback for scripting. At minimum, document the argv/shell-history exposure in the README.
2. **(Low)** Hoist the even/`≥16` validation into `secret.Generate` (and/or validate the `--length` flag in `gen.go`) so its guarantee matches the advertised contract.
3. **(Low)** Add an explicit `n ∈ [1,256]` guard to `uniformIndex` to convert the latent infinite-loop into a clear error.
4. **(Low)** Add a `Split` validation test for an odd length ≥16 (covering `slip039.go:49-51`) and relabel the misleading 15-byte case.
5. **(Low)** Add a distribution/uniformity test for `Generate` (large-sample + a mid-range-`n` `uniformIndex` boundary test).
6. **(Low, optional)** Switch the digest comparison to `crypto/subtle.ConstantTimeCompare`/`hmac.Equal` for defense-in-depth and intent-signaling.
7. **(Low, optional)** Either drop `validatePassphrase` from `Combine` (match the reference) or document the intentional interop-restricting divergence.
8. **(Info)** Add a cheap `len(wordList)==1024 && unique` test; add a first-party encode round-trip at `iterationExponent>1` and `extendable=false`; document that `Split` is single-group/extendable-only by design.

---

## Conclusion

`splitshot`'s cryptographic core is **correct, conformant, and faithful to the Trezor SLIP-0039 reference**. Random secret generation, Shamir splitting, and SLIP-0039 mnemonic encoding — the three areas that must be flawless — are each verified: by exhaustive analysis, by 100%/97.1% unit-test coverage, and by all 45 official test vectors passing. **There are zero confirmed critical or high-severity findings.** The one medium finding (passphrase delivered only via argv) is a legitimate, fixable secret-hygiene gap in an otherwise disciplined tool; the remaining findings are low/info-level hardening, faithful-to-reference timing characteristics that are non-exploitable in this offline context, and test-coverage improvements.

The tool is sound and safe for its stated purpose. Addressing the passphrase-input issue and the low-severity items would bring it to an excellent state.

*This is an internal, partly-automated adversarial review and does not replace a professional human cryptographic audit prior to high-value production deployment.*

---

## Remediation (post-audit, same change as this report)

The audit found zero critical/high issues; the items below were addressed
immediately afterward. The cryptographic core was already correct — these are
hardening and test/coverage improvements.

| # | Severity | Status | What changed |
|---|----------|--------|--------------|
| 1 | Medium | **Fixed** | Added `--ask-passphrase`: prompts on the controlling terminal (`/dev/tty`) with confirmation, so the passphrase never enters argv or shell history. `--passphrase` remains for scripting; the two are mutually exclusive. |
| 2 | Low | **Fixed** | `gen` now validates `--length` (even, ≥16) up front with a clear message instead of relying on the downstream `Split` error. |
| 3 | Low | **Fixed** | `uniformIndex` now errors for `n ∉ [1,256]` instead of looping forever (latent guard). |
| 4 | Low | **Fixed** | Digest comparison switched to `crypto/subtle.ConstantTimeCompare` (defense-in-depth / intent-signaling). |
| 5 | Low | **Fixed** | Dropped `validatePassphrase` from `Combine` to match the reference — recovery is now maximally permissive (better interop). `Split` still validates, mirroring `generate_mnemonics`. |
| 6 | Low | **Fixed** | Added a `Split` validation test for an odd length ≥16 (covers the even-length guard) and relabeled the misleading 15-byte case. |
| 7 | Low | **Fixed** | Added a large-sample distribution test for `Generate` and a mid-range (`n=10`) `uniformIndex` boundary/coverage test. |
| 9 | Info | **Fixed** | Clarified the PBKDF2 iteration-count doc comment (20000 is the total, ≈5000 per round). |
| 8, 10–18 | Info | Acknowledged | Intentional designs (single-group/extendable-only `Split`, permissive multi-group `Combine`, reference-faithful behaviors) and non-crypto/defensive-guard coverage gaps; documented, no code change. |

After these changes: `go vet` + `staticcheck` clean; full suite passes under `-race`
(`secret` 100%, `slip039` ~97%, `pdf` ~98%). The interactive prompt path in the
CLI is the main intentionally-uncovered branch (it requires a real terminal).
