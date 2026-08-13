package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	keyLen = 32 // AES-256

	// defaultIterations follows the OWASP recommendation for
	// PBKDF2-HMAC-SHA256. It costs a few hundred milliseconds on a phone and
	// makes offline guessing roughly six orders of magnitude more expensive
	// than a bare SHA-256 of the password.
	defaultIterations = 600_000
	// minIterations is the floor accepted when *decoding*, so a tampered
	// header cannot talk us into a cheap derivation.
	minIterations = 50_000
)

var errWrongPassword = errors.New("decryption failed: wrong password, or the payload was altered")

// randBytes fills b with cryptographically secure random bytes.
func randBytes(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("secure random source unavailable: %w", err)
	}
	return nil
}

// deriveKey stretches a password into a 32-byte AES-256 key.
//
// PBKDF2-HMAC-SHA256 is used rather than a bare hash because a single SHA-256
// can be guessed billions of times per second on commodity GPUs. It is also
// the strongest KDF available on both sides of this project without any
// external dependency: Go has crypto/pbkdf2 in the standard library, and
// Android exposes it through SecretKeyFactory.
func deriveKey(password string, salt []byte, iterations int) ([]byte, error) {
	if password == "" {
		return nil, errors.New("the password cannot be empty")
	}
	if iterations < minIterations {
		return nil, fmt.Errorf("iteration count must be at least %d", minIterations)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return key, nil
}

// pbkdf2Raw exposes the KDF with an arbitrary output length so the self-test
// can check it against published test vectors.
func pbkdf2Raw(password string, salt []byte, iterations, length int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, length)
}

// wipe overwrites key material so it does not linger in the heap any longer
// than necessary. Not a guarantee (Go may have copied it during a GC move),
// but it shortens the window a memory dump could catch it in.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext with AES-256-GCM, authenticating aad alongside it.
func seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// open authenticates and decrypts. Any failure — wrong password, flipped bit,
// edited header — surfaces as the same error, so nothing is leaked about which
// part went wrong.
func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errWrongPassword
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errWrongPassword
	}
	return plaintext, nil
}

// gcmOverhead is the number of bytes GCM adds on top of the plaintext.
const gcmOverhead = 16
