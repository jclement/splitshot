# splitshot

**Cut your most precious secret into pieces, scatter the pieces across people and places who don't know about each other, and sleep like someone who has read a threat model.**

> Because trusting one piece of paper was getting too exciting.

`splitshot` generates a cryptographically obnoxious secret and splits it into
`N`-of-`M` shares using [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
Shamir's Secret Sharing. Any **N** shares rebuild the secret. Any **fewer than N**
reveal *nothing* — not "kind of less," not "a head start for the NSA," **nothing**,
in the cold information-theoretic sense that makes mathematicians smug.

Single static binary. No CGO. No network. No telemetry, no "anonymous usage
statistics," no cloud, no account, no Terms of Service you didn't read. All the
crypto is implemented locally and checked against the official SLIP-0039 test
vectors, because "trust me" is not a cipher.

---

## A short film, starring Bob

Bob has a Vault. Capital V. Behind one passphrase sits Bob's entire digital
existence: his [KeePass](https://keepass.info/) database, or his
[`age`](https://github.com/FiloSottile/age) identity, or his 1Password vault —
pick your poison. Inside: every password, the wallet, the photos, the tax stuff,
the half-written manifesto. **One** key unlocks all of it.

Bob has done the reading. He knows there are exactly two ways this ends:

1. **He loses it.** The laptop dies. The house floods. He forgets the passphrase
   he swore he'd never forget. The Vault is now a very secure brick. Everything
   inside is gone *forever* — and "forever" in cryptography means forever.
2. **Someone finds it.** The sticky note. The "passwords.txt" on the desktop.
   The note in his phone helpfully synced to three companies and a subpoena.
   Now someone *else* has everything.

One copy is a single point of failure. More copies are more doors to kick in.
Bob is trapped between **losing it** and **leaking it**, which is the entire
miserable history of secret-keeping in one sentence.

Bob does not want to trust a company. Bob does not want to trust a government.
Bob, frankly, does not fully trust *Bob*. So Bob reaches for math.

### Bob splits the key

```console
$ splitshot gen
```

Out comes a 32-character, ~210-bit secret (in a tasteful box) and **five**
word-shares. Bob chose the defaults: **3-of-5**. Any three shares rebuild the
key. Any two are confetti.

Now Bob scatters them, because a backup in one place is just a liability with
good intentions:

| Share | Goes to | Cover story |
|------:|---------|-------------|
| 1 | **Uncle Fred**, a coffee tin in Ohio | "It's a chili recipe, Fred. Don't lose it." |
| 2 | **The safe-deposit box** at the bank | The bank thinks it knows things. It does not. |
| 3 | **Sewn into the waistband of his lucky underwear** | Do not ask. Do not do this. |
| 4 | **Alice**, who is reliable | Lives on one continent. |
| 5 | **Valerie**, who is also reliable | Lives on a *different* continent, on purpose. |

No single location holds the key. No single person can be coerced, bribed, or
politely served a warrant into surrendering it, because no single person *has*
it. Three of these five must cooperate before the Vault so much as blinks.

### Eve has entered the chat

Eve wants Bob's key. Eve always wants Bob's key. Over a productive month Eve
cracks the safe-deposit box and, on a good day, relieves Uncle Fred of his
"recipe." **Two shares!** She sprints home, feeds them to her own copy of
`splitshot`, and receives... a perfectly valid-looking, utterly wrong answer.

That's the point. Two-of-five isn't *almost* the secret — it is statistically
indistinguishable from noise. Eve learned nothing. She'd need a third share, and
the third share is in Bob's underwear, and even Eve has standards.

Bob can lose **any two** shares (fire, flood, forgetful Fred) and still recover.
An attacker must compromise **three separate** locations before learning a single
bit. *Losing it* and *leaking it* are now different problems, and both got
dramatically harder. Mission accomplished, no cloud required.

### Bob comes home

A year later, Bob needs in. Fred mails the tin, the bank opens the box, the
underwear is retired with honors. Three shares. Bob, on a freshly-wiped offline
laptop, types:

```console
$ splitshot combine
<paste share 1>
<paste share 2>
<paste share 3>
^D
```

The Vault opens. Bob exhales. Eve, somewhere, is still holding two useless lists
of words and a grudge.

---

## Okay, but actually: how it works

`splitshot` is a thin, friendly wrapper around **SLIP-0039**, the SatoshiLabs
standard purpose-built for splitting secrets into mnemonic words. Highlights for
the suspicious:

- **Threshold secret sharing (Shamir over GF(256)).** The secret is a point on a
  polynomial; each share is another point. You need `N` points to reconstruct the
  curve. Fewer than `N` and the curve could be literally anything. This is not
  obfuscation — it's provable.
- **Self-describing shares.** Each share knows its own index and the threshold,
  so recovery never needs you to remember "was it 3-of-5 or 2-of-4?" — just feed
  in enough shares.
- **Built-in integrity check.** A reconstructed-from-wrong-shares secret is
  *detected*, not silently returned.
- **Optional passphrase = second factor + plausible deniability.** With the
  *wrong* passphrase, the shares recover a *different, valid-looking* secret
  instead of erroring. Translation: Bob can hand a coerced passphrase to an
  adversary and watch them unlock a decoy. (See "Spy vs Spy," above.)
- **Real randomness.** Secrets come from the OS CSPRNG (`crypto/rand`), with
  rejection sampling so there's zero modulo bias. No "clever" homebrew RNG.

Threshold convention: **`-n` = shares required to recover (N)**, **`-m` = total
shares produced (M)**. Constraint: `2 ≤ n ≤ m ≤ 16`. Default: **3-of-5**.

---

## Install

```bash
# Homebrew
brew install jclement/tap/splitshot

# Go
go install github.com/jclement/splitshot/cmd/splitshot@latest
```

Or grab a static binary from [Releases](https://github.com/jclement/splitshot/releases)
and put it on your `PATH`. It's one file. It has no dependencies. It will outlive
several startups.

---

## Using it

### `gen` — make a new secret and split it

For when the secret doesn't exist yet (a fresh KeePass/age/1Password master key):

```bash
splitshot gen                 # 32-char ~210-bit secret, 3-of-5, shown once
splitshot gen -n 2 -m 3       # 2-of-3 instead
splitshot gen -l 16           # shorter secret → 20-word shares
splitshot gen --charset safe  # keyboard-friendly symbols only
```

The secret is printed **once**, in a box, in green, with a warning. Write it into
your vault now — it is not stored and will not be shown again. The shares go to
stdout; everything else (the secret, banners, notices) goes to stderr, so:

```bash
splitshot gen > shares.txt     # captures ONLY the shares; secret stays on screen
```

### `split` — split a secret you already have

For when the Vault key already exists and you just want it backed up properly:

```bash
printf '%s' 'correct-horse-battery-staple!!' | splitshot split -n 3 -m 5
splitshot split --secret-file vaultkey.txt
```

(Secrets must be at least 16 bytes and an even number of bytes — a SLIP-0039 rule,
not ours.)

### `combine` — put the secret back together

Reads share mnemonics from stdin, one per line, until EOF (`Ctrl-D`). Blank lines,
`# comments`, and `---` separators are ignored, so a lightly-annotated paste just
works:

```bash
splitshot combine < shares.txt
# or paste interactively and press Ctrl-D
```

Give it **N** shares and it reconstructs the secret. Give it fewer and it tells
you, politely, that you're short. Give it the wrong passphrase and it cheerfully
hands you a decoy.

### `pdf` — analog cold storage

Screens get keylogged, drives die, clouds get breached and/or subpoenaed. Paper,
stored in a tin in Ohio, does none of those things. `splitshot` generates a single
multi-page **backup PDF** — one page per share — sized for exactly the right
number of words:

```bash
splitshot gen --pdf bob-backup.pdf        # generate + split + one PDF, all at once
splitshot pdf -n 3 -m 5 -o blank.pdf      # just the blank templates, no secret involved
```

By default the pages are **blank handwriting templates**: numbered boxes, the
parameters (#X of M, N required, a Set ID to match the set), and recovery
instructions — but **never the words**. The renderer is never even handed your
secret. You write the words in by hand, and the paper never touches a printer
queue.

If you trust your printer (airgapped, owned, watched), you can opt in to printed
words:

```bash
echo -n 'my-vault-key' | splitshot pdf -p -n 3 -m 5 -o filled.pdf
```

The look is deliberately **retro Turbo-Vision**: monospace, hard black borders,
grey shaded panels, inverse title bar. It looks like it was printed by a machine
that does not phone home. Because it was.

---

## Command & flag reference

| Command | What it does |
|---------|--------------|
| `splitshot gen` | Generate a random secret and split it into N-of-M shares |
| `splitshot split` | Split an existing secret (stdin or `--secret-file`) |
| `splitshot combine` | Reconstruct a secret from share mnemonics on stdin |
| `splitshot pdf` | Generate a multi-page backup PDF (`-p` to print the words) |
| `splitshot version` | Print version and build info |

| Flag | Commands | Description | Default |
|------|----------|-------------|---------|
| `-n, --threshold` | gen, split, pdf | Shares required to recover (N) | `3` |
| `-m, --shares` | gen, split, pdf | Total shares to produce (M) | `5` |
| `-l, --length` | gen, pdf | Secret length (even, ≥16; 16→20-word shares, 32→33-word) | `32` |
| `--charset` | gen | `alphanumeric`, `alpha`, `digits`, `hex`, `safe`, `ascii`, or a literal set | `ascii` |
| `--passphrase` | gen, split, combine, pdf | Optional passphrase / second factor | `""` |
| `--pdf` | gen, split | Write a single multi-page backup PDF to this path | — |
| `-p, --fill` | pdf | Read a secret from stdin and **print** the words onto the pages | `false` |
| `-o, --out` | pdf | Output PDF path | `splitshot-backup.pdf` |
| `--show-secret` | gen, split | Echo the secret once (gen on, split off) | — |

---

## Operational paranoia (the fun kind)

- **A single share reveals nothing.** Store the shares *apart*. The whole design
  assumes some of them will be lost or stolen — that's not a bug, it's the job.
- **`-n` of `-m` is your blast radius.** 3-of-5 means you can lose 2 and survive,
  and an attacker needs 3 to win. Tune to taste and trust levels.
- **The passphrase is a real second factor.** No passphrase is fine for most
  people. A passphrase means the words alone aren't enough — and a *decoy*
  passphrase means a coerced unlock reveals a decoy. There's no way to tell from
  the shares which passphrase is "right."
- **PDFs are blank by default and written `0600`.** The words only hit paper if
  you explicitly ask (`pdf -p`), and even then it's your printer's problem now.
- **Recover on a trusted, offline machine.** ~210 bits of entropy is irrelevant
  if a keylogger watches you type the recovered key. Math protects the storage,
  not the keyboard.
- **No accounts. No cloud. No phone-home.** This tool does not know who you are
  and has no way to find out. That is a feature, and increasingly a political one.

---

## Development

| Command | What it does |
|---------|-------------|
| `mise install` | Install all tools (Go, goreleaser, staticcheck) |
| `mise run test` | All tests, race detector + coverage |
| `mise run lint` | `go vet` + `staticcheck` (zero warnings) |
| `mise run fmt` | Format |
| `mise run build` | Build `bin/splitshot` |
| `mise run dev -- gen -n 2 -m 3` | Run from source |
| `mise run release` | Tag and push a release |

The correctness-critical bits (SLIP-0039: GF(256), RS1024, Feistel/PBKDF2) are
implemented locally and verified against the **official SLIP-0039 test vectors**.
See [DESIGN.md](DESIGN.md) for the architecture and the gory crypto details.

---

## License

MIT. © 2026 Jeff Clement. Do crimes responsibly. (Kidding. Mostly. Back up your keys.)
