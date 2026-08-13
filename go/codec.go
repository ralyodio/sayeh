package main

import (
	"errors"
	"strings"
)

// Zero-width carriers.
//
// U+200C (ZERO WIDTH NON-JOINER) is intentionally absent from every alphabet:
// it is a meaningful character in Persian/Arabic script (نیم‌فاصله), so using
// it as a data carrier would visibly corrupt the cover text.
const (
	zwSpace  = '​' // ZERO WIDTH SPACE
	zwJoiner = '‍' // ZERO WIDTH JOINER
	zwWordJn = '⁠' // WORD JOINER
	zwPlus   = '⁤' // INVISIBLE PLUS
)

// Codec selects how many bits each invisible rune carries.
type Codec byte

const (
	// CodecB4 packs 2 bits per rune over a 4-symbol alphabet. Default: it
	// halves the payload size compared to the classic 1-bit encoding.
	CodecB4 Codec = 4
	// CodecB2 packs 1 bit per rune using only ZWSP/ZWJ. Larger, but survives
	// the widest range of sanitizers and is what v1/v2 of this tool used.
	CodecB2 Codec = 2
)

func (c Codec) String() string {
	switch c {
	case CodecB4:
		return "B4 (2 bits/char)"
	case CodecB2:
		return "B2 (1 bit/char)"
	default:
		return "unknown"
	}
}

// ParseCodec maps a CLI value onto a codec.
func ParseCodec(s string) (Codec, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "b4", "4", "", "default":
		return CodecB4, nil
	case "b2", "2", "compat", "legacy":
		return CodecB2, nil
	}
	return 0, errors.New(`codec must be "b4" or "b2"`)
}

var (
	alphabetB4 = [4]rune{zwSpace, zwJoiner, zwWordJn, zwPlus}
	// alphabetB2 keeps the historic mapping: 1 -> ZWSP, 0 -> ZWJ.
	alphabetB2 = [2]rune{zwJoiner, zwSpace}
)

// IsCarrier reports whether r is one of the invisible characters this tool
// uses to carry data.
func IsCarrier(r rune) bool {
	return r == zwSpace || r == zwJoiner || r == zwWordJn || r == zwPlus
}

// Encode renders raw bytes as a run of invisible characters, MSB first.
func Encode(data []byte, codec Codec) string {
	var b strings.Builder

	switch codec {
	case CodecB4:
		b.Grow(len(data) * 4 * 3) // 4 runes per byte, 3 UTF-8 bytes per rune
		for _, v := range data {
			b.WriteRune(alphabetB4[v>>6&3])
			b.WriteRune(alphabetB4[v>>4&3])
			b.WriteRune(alphabetB4[v>>2&3])
			b.WriteRune(alphabetB4[v&3])
		}
	default:
		b.Grow(len(data) * 8 * 3)
		for _, v := range data {
			for i := 7; i >= 0; i-- {
				b.WriteRune(alphabetB2[v>>uint(i)&1])
			}
		}
	}
	return b.String()
}

// Decode reads invisible characters back into bytes. Runes outside the
// codec's alphabet are skipped, so visible cover text is transparent. Trailing
// bits that do not complete a byte are discarded.
func Decode(text string, codec Codec) []byte {
	out := make([]byte, 0, len(text)/3/4+8)

	var acc byte
	var have uint

	for _, r := range text {
		var sym byte
		var width uint

		switch codec {
		case CodecB4:
			switch r {
			case zwSpace:
				sym, width = 0, 2
			case zwJoiner:
				sym, width = 1, 2
			case zwWordJn:
				sym, width = 2, 2
			case zwPlus:
				sym, width = 3, 2
			default:
				continue
			}
		default:
			switch r {
			case zwSpace:
				sym, width = 1, 1
			case zwJoiner:
				sym, width = 0, 1
			default:
				continue
			}
		}

		acc = acc<<width | sym
		have += width
		if have == 8 {
			out = append(out, acc)
			acc, have = 0, 0
		}
	}
	return out
}

// Strip removes every carrier character from s. Used to sanitize a cover text
// before injection (so two payloads can never interleave) and exposed to the
// user as a "clean this text" command.
func Strip(s string) string {
	if !strings.ContainsFunc(s, IsCarrier) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if IsCarrier(r) {
			return -1
		}
		return r
	}, s)
}

// CountCarriers returns how many invisible characters s contains.
func CountCarriers(s string) int {
	n := 0
	for _, r := range s {
		if IsCarrier(r) {
			n++
		}
	}
	return n
}

// Inject places payload inside cover, right after the first visible rune, so
// the invisible run is anchored to real text instead of dangling at the very
// start of the string. Carriers already present in cover are removed first.
func Inject(cover, payload string) string {
	clean := []rune(Strip(cover))
	if len(clean) == 0 {
		return payload
	}
	return string(clean[0]) + payload + string(clean[1:])
}
