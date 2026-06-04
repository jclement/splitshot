// wordlist.go embeds the official 1024-word SLIP-0039 wordlist and provides
// the word↔index conversions used to encode and decode mnemonics. The list is
// embedded so the binary stays self-contained — no external files at runtime.
package slip039

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed wordlist.txt
var wordlistRaw string

// wordList holds the 1024 words in canonical order; wordIndex is its inverse.
var (
	wordList  []string
	wordIndex map[string]int
)

// init parses the embedded wordlist once and panics if it is not exactly 1024
// words — a malformed list would silently corrupt every mnemonic, so failing
// loudly at startup is the only sane option.
func init() {
	wordList = append(wordList, strings.Fields(wordlistRaw)...)
	if len(wordList) != radix {
		panic(fmt.Sprintf("slip039: wordlist must contain %d words, got %d", radix, len(wordList)))
	}
	wordIndex = make(map[string]int, radix)
	for i, w := range wordList {
		wordIndex[w] = i
	}
}

// wordsFromIndices maps a slice of 10-bit indices to their words.
func wordsFromIndices(indices []int) []string {
	words := make([]string, len(indices))
	for i, idx := range indices {
		words[i] = wordList[idx]
	}
	return words
}

// mnemonicToIndices splits a mnemonic string into its word indices. Words are
// lowercased before lookup so casing in handwritten backups doesn't matter.
// Returns an error naming the first unrecognized word.
func mnemonicToIndices(mnemonic string) ([]int, error) {
	fields := strings.Fields(mnemonic)
	indices := make([]int, len(fields))
	for i, w := range fields {
		idx, ok := wordIndex[strings.ToLower(w)]
		if !ok {
			return nil, fmt.Errorf("invalid mnemonic word %q", w)
		}
		indices[i] = idx
	}
	return indices, nil
}
