package main

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// HideOptions controls how a secret is packed.
type HideOptions struct {
	Password   string // empty means "do not encrypt"
	Codec      Codec
	Iterations int
	NoCompress bool
}

// Report describes what was produced or found, for display purposes.
type Report struct {
	Encrypted  bool
	Compressed bool
	Codec      Codec
	Iterations int
	SecretSize int // plaintext bytes (0 when unknown, i.e. scanning a sealed payload)
	Container  int // container bytes on the wire
	Carriers   int // invisible characters
}

// Hide packs secret into an invisible payload and injects it into cover.
func Hide(cover, secret string, opts HideOptions) (string, Report, error) {
	if secret == "" {
		return "", Report{}, errors.New("the secret is empty — there is nothing to hide")
	}
	if opts.Codec == 0 {
		opts.Codec = CodecB4
	}
	if opts.Iterations == 0 {
		opts.Iterations = defaultIterations
	}

	body := []byte(secret)
	rep := Report{Codec: opts.Codec, SecretSize: len(body)}

	// Compression happens before encryption: it shrinks the payload — often by
	// 3-5x on natural language, which matters a lot when every byte costs four
	// invisible characters — and it is safe here because the attacker never
	// gets to inject chosen plaintext into the secret.
	if !opts.NoCompress {
		if squeezed, err := deflate(body); err == nil && len(squeezed) < len(body) {
			body = squeezed
			rep.Compressed = true
		}
	}

	c := &container{}
	if rep.Compressed {
		c.flags |= flagCompressed
	}

	var payload []byte

	if opts.Password == "" {
		inner, err := packInner(body, false)
		if err != nil {
			return "", Report{}, err
		}
		payload = inner
		c.payload = payload
	} else {
		c.flags |= flagEncrypted
		c.kdf = kdfPBKDF2SHA256
		c.iterations = uint32(opts.Iterations)
		c.salt = make([]byte, saltLen)
		c.nonce = make([]byte, nonceLen)
		if err := randBytes(c.salt); err != nil {
			return "", Report{}, err
		}
		if err := randBytes(c.nonce); err != nil {
			return "", Report{}, err
		}

		inner, err := packInner(body, true)
		if err != nil {
			return "", Report{}, err
		}

		key, err := deriveKey(opts.Password, c.salt, opts.Iterations)
		if err != nil {
			return "", Report{}, err
		}
		defer wipe(key)

		// The header is authenticated, so the declared length must be the
		// final sealed length — computed up front, before sealing.
		aad := c.header(len(inner) + gcmOverhead)
		payload, err = seal(key, c.nonce, inner, aad)
		if err != nil {
			return "", Report{}, err
		}
		c.payload = payload

		rep.Encrypted = true
		rep.Iterations = opts.Iterations
	}

	raw := c.marshal()
	invisible := Encode(raw, opts.Codec)

	rep.Container = len(raw)
	rep.Carriers = utf8.RuneCountInString(invisible)

	return Inject(cover, invisible), rep, nil
}

// Scan recovers and identifies a payload without decrypting it. The returned
// container is still sealed; pass it to Unseal with a password.
func Scan(text string) (*container, []byte, Codec, Report, error) {
	for _, codec := range []Codec{CodecB4, CodecB2} {
		raw := Decode(text, codec)
		if len(raw) == 0 {
			continue
		}
		c, header, err := parseContainer(raw)
		if err != nil {
			// Only a magic mismatch means "wrong codec, keep looking"; a real
			// structural problem should be reported to the user as-is.
			if errors.Is(err, errBadMagic) || errors.Is(err, errNoPayload) {
				continue
			}
			return nil, nil, codec, Report{}, err
		}
		rep := Report{
			Encrypted:  c.encrypted(),
			Compressed: c.compressed(),
			Codec:      codec,
			Iterations: int(c.iterations),
			Container:  len(header) + len(c.payload),
			Carriers:   CountCarriers(text),
		}
		return c, header, codec, rep, nil
	}

	// Nothing modern matched. Fall back to the v1/v2 layouts.
	if secret, ok := decodeLegacy(text); ok {
		return nil, nil, CodecB2, Report{
			Codec:      CodecB2,
			SecretSize: len(secret),
			Carriers:   CountCarriers(text),
		}, errLegacyPlain{secret}
	}

	if CountCarriers(text) == 0 {
		return nil, nil, 0, Report{}, errNoPayload
	}
	return nil, nil, 0, Report{}, errBadMagic
}

// Unseal turns a scanned container into the original secret. password is
// ignored for unencrypted payloads.
func Unseal(c *container, header []byte, password string) (string, error) {
	var inner []byte

	if c.encrypted() {
		if password == "" {
			return "", errors.New("this payload is encrypted and needs a password")
		}
		key, err := deriveKey(password, c.salt, int(c.iterations))
		if err != nil {
			return "", err
		}
		defer wipe(key)

		inner, err = open(key, c.nonce, c.payload, header)
		if err != nil {
			return "", err
		}
	} else {
		inner = c.payload
	}

	body, err := unpackInner(inner)
	if err != nil {
		return "", err
	}

	if c.compressed() {
		body, err = inflate(body)
		if err != nil {
			return "", fmt.Errorf("the payload could not be decompressed: %w", err)
		}
	}
	if !utf8.Valid(body) {
		return "", errors.New("the recovered data is not valid text")
	}
	return string(body), nil
}

// Reveal is the one-shot path: scan, ask for a password if needed, unseal.
// askPassword may be nil for payloads that are known to be unencrypted.
func Reveal(text string, askPassword func() (string, bool)) (string, Report, error) {
	c, header, _, rep, err := Scan(text)
	if err != nil {
		var legacy errLegacyPlain
		if errors.As(err, &legacy) {
			return legacy.secret, rep, nil
		}
		return "", rep, err
	}

	password := ""
	if c.encrypted() {
		if askPassword == nil {
			return "", rep, errors.New("this payload is encrypted and needs a password")
		}
		pw, ok := askPassword()
		if !ok {
			return "", rep, errAborted
		}
		password = pw
	}

	secret, err := Unseal(c, header, password)
	if err != nil {
		return "", rep, err
	}
	rep.SecretSize = len(secret)
	return secret, rep, nil
}

var errAborted = errors.New("operation cancelled")

// errLegacyPlain carries a secret recovered from a pre-v3 payload, which has
// no container to hand back.
type errLegacyPlain struct{ secret string }

func (errLegacyPlain) Error() string { return "legacy payload" }

// decodeLegacy reads the v1 (STEGO_V1:) and v2 (STEGO_RAW:) layouts so older
// messages keep working. v2's encrypted form (STEGO_ENC:) is not supported —
// it derived its key with a bare SHA-256 and is deliberately not carried
// forward.
func decodeLegacy(text string) (string, bool) {
	raw := Decode(text, CodecB2)
	if len(raw) == 0 {
		return "", false
	}
	for _, prefix := range []string{"STEGO_V1:", "STEGO_RAW:"} {
		if bytes.HasPrefix(raw, []byte(prefix)) {
			body := raw[len(prefix):]
			if utf8.Valid(body) {
				return string(body), true
			}
		}
	}
	return "", false
}

// LegacyEncrypted reports whether text holds a v2 STEGO_ENC: payload, so the
// user can be told exactly why it is being refused instead of getting a
// generic "unknown header".
func LegacyEncrypted(text string) bool {
	raw := Decode(text, CodecB2)
	return bytes.HasPrefix(raw, []byte("STEGO_ENC:"))
}

func deflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inflate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	// Bound the output so a malicious payload cannot be a decompression bomb.
	out, err := io.ReadAll(io.LimitReader(r, maxPayload+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxPayload {
		return nil, errors.New("decompressed data exceeds the size limit")
	}
	return out, nil
}

// Describe renders a Report as a short human-readable summary.
func (r Report) Describe() string {
	var parts []string
	if r.Encrypted {
		parts = append(parts, fmt.Sprintf("AES-256-GCM, PBKDF2-SHA256 x%d", r.Iterations))
	} else {
		parts = append(parts, "not encrypted")
	}
	if r.Compressed {
		parts = append(parts, "DEFLATE")
	}
	parts = append(parts, r.Codec.String())
	return strings.Join(parts, " | ")
}
