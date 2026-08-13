package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// SelfTest exercises the primitives, the wire format and the failure paths.
// It exists so a user can prove the build on their machine behaves correctly
// before trusting anything to it.
func SelfTest(w io.Writer) error {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"PBKDF2-HMAC-SHA256 known-answer (RFC 7914 §11)", testKDFVectors},
		{"zero-width codec round-trip, all byte values", testCodecRoundTrip},
		{"codec alphabets exclude U+200C (Persian ZWNJ)", testNoZWNJ},
		{"hide/reveal round-trip without a password", testPlainRoundTrip},
		{"hide/reveal round-trip with a password", testSealedRoundTrip},
		{"unicode payload survives (Persian + emoji)", testUnicodeRoundTrip},
		{"wrong password is rejected", testWrongPassword},
		{"flipped ciphertext bit is rejected", testTamperCiphertext},
		{"edited header is rejected (AAD binding)", testTamperHeader},
		{"downgraded iteration count is rejected", testIterationFloor},
		{"padding hides the exact message length", testPadding},
		{"cover text is preserved verbatim", testCoverPreserved},
		{"legacy v1/v2 plain payloads still decode", testLegacy},
		{"cross-implementation vector matches Android", testCrossVector},
	}

	failures := 0
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Fprintf(w, "  FAIL  %s\n          %v\n", c.name, err)
			failures++
			continue
		}
		fmt.Fprintf(w, "  ok    %s\n", c.name)
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d checks failed", failures, len(checks))
	}
	return nil
}

func testKDFVectors() error {
	vectors := []struct {
		password, salt string
		iter, length   int
		want           string
	}{
		{"passwd", "salt", 1, 64,
			"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
				"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, 64,
			"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
				"a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
		{"password", "salt", 4096, 32,
			"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}

	for _, v := range vectors {
		got, err := pbkdf2Raw(v.password, []byte(v.salt), v.iter, v.length)
		if err != nil {
			return err
		}
		if hex.EncodeToString(got) != v.want {
			return fmt.Errorf("vector %q/%q iter=%d: got %s", v.password, v.salt, v.iter, hex.EncodeToString(got))
		}
	}
	return nil
}

func testCodecRoundTrip() error {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	for _, codec := range []Codec{CodecB4, CodecB2} {
		// Split on a rune boundary, then interleave visible text: the decoder
		// must ignore everything that is not a carrier.
		runes := []rune(Encode(data, codec))
		half := len(runes) / 2
		noisy := "سلام" + string(runes[:half]) + " hello world " + string(runes[half:]) + "!"
		if got := Decode(noisy, codec); !bytes.Equal(got, data) {
			return fmt.Errorf("%v: round-trip mismatch (%d of %d bytes recovered)", codec, len(got), len(data))
		}
	}
	return nil
}

func testNoZWNJ() error {
	for _, r := range append(alphabetB4[:], alphabetB2[:]...) {
		if r == '‌' {
			return fmt.Errorf("U+200C is used as a carrier; it is a meaningful character in Persian")
		}
	}
	if IsCarrier('‌') {
		return fmt.Errorf("IsCarrier claims U+200C is a carrier")
	}
	// A Persian half-space in the cover must survive untouched.
	const persian = "نیم‌فاصله"
	if Strip(persian) != persian {
		return fmt.Errorf("Strip mangled a Persian half-space")
	}
	return nil
}

func testPlainRoundTrip() error {
	return roundTrip("The quick brown fox jumps over the lazy dog.", "", CodecB4)
}

func testSealedRoundTrip() error {
	for _, codec := range []Codec{CodecB4, CodecB2} {
		if err := roundTrip("attack at dawn", "correct horse battery staple", codec); err != nil {
			return err
		}
	}
	return nil
}

func testUnicodeRoundTrip() error {
	const secret = "پیام محرمانه ۱۲۳ — مختلط with English 🔐🕵️"
	return roundTrip(secret, "رمز عبور فارسی", CodecB4)
}

func roundTrip(secret, password string, codec Codec) error {
	const cover = "This is an ordinary looking sentence."

	stego, _, err := Hide(cover, secret, HideOptions{
		Password:   password,
		Codec:      codec,
		Iterations: minIterations, // keep the self-test fast
	})
	if err != nil {
		return err
	}

	got, _, err := Reveal(stego, func() (string, bool) { return password, true })
	if err != nil {
		return err
	}
	if got != secret {
		return fmt.Errorf("recovered %q, want %q", got, secret)
	}
	return nil
}

func testWrongPassword() error {
	stego, _, err := Hide("cover", "secret", HideOptions{Password: "right", Iterations: minIterations})
	if err != nil {
		return err
	}
	if _, _, err := Reveal(stego, func() (string, bool) { return "wrong", true }); err == nil {
		return fmt.Errorf("a wrong password was accepted")
	}
	return nil
}

func testTamperCiphertext() error {
	c, header, err := buildContainer("secret message", "pw")
	if err != nil {
		return err
	}
	c.payload[len(c.payload)/2] ^= 0x01
	if _, err := Unseal(c, header, "pw"); err == nil {
		return fmt.Errorf("a flipped ciphertext bit was accepted")
	}
	return nil
}

func testTamperHeader() error {
	c, header, err := buildContainer("secret message", "pw")
	if err != nil {
		return err
	}
	// Rewrite the compressed flag in the AAD copy. GCM must notice.
	tampered := append([]byte(nil), header...)
	tampered[5] ^= flagCompressed
	if _, err := Unseal(c, tampered, "pw"); err == nil {
		return fmt.Errorf("an edited header was accepted")
	}
	return nil
}

func testIterationFloor() error {
	stego, _, err := Hide("cover", "secret", HideOptions{Password: "pw", Iterations: minIterations})
	if err != nil {
		return err
	}
	raw := Decode(stego, CodecB4)
	// Force the stored iteration count down to 1.
	raw[8], raw[9], raw[10], raw[11] = 0, 0, 0, 1
	if _, _, err := parseContainer(raw); err == nil {
		return fmt.Errorf("an iteration count of 1 was accepted")
	}
	return nil
}

func testPadding() error {
	// Two secrets that differ in length but land in the same 64-byte bucket
	// must produce identical ciphertext sizes.
	var sizes []int
	for _, n := range []int{1, 5, 9} {
		c, _, err := buildContainer(strings.Repeat("x", n), "pw")
		if err != nil {
			return err
		}
		sizes = append(sizes, len(c.payload))
	}
	for i := 1; i < len(sizes); i++ {
		if sizes[i] != sizes[0] {
			return fmt.Errorf("payload sizes leak the message length: %v", sizes)
		}
	}
	return nil
}

func testCoverPreserved() error {
	const cover = "سلام دنیا!\nLine two.\tTabbed."
	stego, _, err := Hide(cover, "hi", HideOptions{})
	if err != nil {
		return err
	}
	if got := Strip(stego); got != cover {
		return fmt.Errorf("cover changed:\n got %q\nwant %q", got, cover)
	}
	return nil
}

func testLegacy() error {
	const secret = "legacy message"
	for _, prefix := range []string{"STEGO_V1:", "STEGO_RAW:"} {
		stego := Inject("cover text", Encode([]byte(prefix+secret), CodecB2))
		got, _, err := Reveal(stego, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		if got != secret {
			return fmt.Errorf("%s: recovered %q", prefix, got)
		}
	}
	return nil
}

// testCrossVector pins the exact bytes the Android implementation must agree
// on. Both sides derive the same key, seal the same plaintext with the same
// nonce, and must land on the same ciphertext.
func testCrossVector() error {
	const (
		password = "Sayeh"
		wantHex  = "83f9f35b42ce634a95c984aad7a48dbe9bed8c120114341464ee1b6405f72398"
	)
	salt := bytes.Repeat([]byte{0xA5}, saltLen)
	nonce := bytes.Repeat([]byte{0x5A}, nonceLen)

	key, err := deriveKey(password, salt, minIterations)
	if err != nil {
		return err
	}
	defer wipe(key)

	sealed, err := seal(key, nonce, []byte("cross-implementation vector"), []byte("ZWS3-AAD"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(sealed)
	if got := hex.EncodeToString(sum[:]); got != wantHex {
		return fmt.Errorf("SHA-256 of the sealed vector is %s, want %s", got, wantHex)
	}
	return nil
}

// buildContainer produces a sealed container plus its AAD, for the tamper
// tests that need to reach inside.
func buildContainer(secret, password string) (*container, []byte, error) {
	stego, _, err := Hide("cover", secret, HideOptions{Password: password, Iterations: minIterations})
	if err != nil {
		return nil, nil, err
	}
	raw := Decode(stego, CodecB4)
	c, header, err := parseContainer(raw)
	if err != nil {
		return nil, nil, err
	}
	// parseContainer hands back sub-slices of raw; copy so tests can mutate.
	c.payload = append([]byte(nil), c.payload...)
	return c, append([]byte(nil), header...), nil
}
