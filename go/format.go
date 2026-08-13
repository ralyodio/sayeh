package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire format v3. See ../SPEC.md — the Android app parses the exact same bytes.
const (
	magic   = "ZWS3"
	version = 3

	flagEncrypted  = 1 << 0
	flagCompressed = 1 << 1

	kdfNone         = 0
	kdfPBKDF2SHA256 = 1

	saltLen  = 16
	nonceLen = 12

	headerFixed = 8  // magic + version + flags + kdf + reserved
	lenField    = 4  // payloadLen
	padBlock    = 64 // inner frame is padded to a multiple of this when encrypted

	// maxPayload bounds allocations when parsing hostile input.
	maxPayload = 16 << 20
)

var (
	errNoPayload  = errors.New("no hidden data found in this text")
	errBadMagic   = errors.New("invisible characters were found, but they are not a Sayeh payload (truncated, reformatted, or produced by another tool)")
	errTruncated  = errors.New("the payload is truncated — the text was cut off or reformatted in transit")
	errBadVersion = errors.New("this payload was made by a newer version of Sayeh")
)

// container is the parsed, still-sealed form of a payload.
type container struct {
	flags      byte
	kdf        byte
	iterations uint32
	salt       []byte
	nonce      []byte
	payload    []byte
}

func (c *container) encrypted() bool  { return c.flags&flagEncrypted != 0 }
func (c *container) compressed() bool { return c.flags&flagCompressed != 0 }

// header returns every byte that precedes the payload, including the length
// field. It doubles as the GCM additional authenticated data, which is what
// binds the KDF parameters and the declared length to the ciphertext.
func (c *container) header(payloadLen int) []byte {
	buf := make([]byte, 0, headerFixed+4+saltLen+nonceLen+lenField)
	buf = append(buf, magic...)
	buf = append(buf, version, c.flags, c.kdf, 0)

	if c.encrypted() {
		buf = binary.BigEndian.AppendUint32(buf, c.iterations)
		buf = append(buf, c.salt...)
		buf = append(buf, c.nonce...)
	}
	return binary.BigEndian.AppendUint32(buf, uint32(payloadLen))
}

// marshal serializes header + payload.
func (c *container) marshal() []byte {
	return append(c.header(len(c.payload)), c.payload...)
}

// parseContainer validates and splits raw bytes recovered from the carriers.
// It returns the container plus the header slice used as AAD.
func parseContainer(raw []byte) (*container, []byte, error) {
	if len(raw) < headerFixed+lenField {
		if len(raw) == 0 {
			return nil, nil, errNoPayload
		}
		return nil, nil, errBadMagic
	}
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, nil, errBadMagic
	}
	if raw[4] != version {
		return nil, nil, errBadVersion
	}

	c := &container{flags: raw[5], kdf: raw[6]}
	off := headerFixed

	if c.encrypted() {
		need := off + 4 + saltLen + nonceLen + lenField
		if len(raw) < need {
			return nil, nil, errTruncated
		}
		if c.kdf != kdfPBKDF2SHA256 {
			return nil, nil, fmt.Errorf("unsupported key derivation function id %d", c.kdf)
		}
		c.iterations = binary.BigEndian.Uint32(raw[off:])
		off += 4
		c.salt = raw[off : off+saltLen]
		off += saltLen
		c.nonce = raw[off : off+nonceLen]
		off += nonceLen

		if c.iterations < minIterations {
			return nil, nil, fmt.Errorf("refusing payload: iteration count %d is below the safe minimum of %d", c.iterations, minIterations)
		}
	} else if c.kdf != kdfNone {
		return nil, nil, errBadMagic
	}

	if len(raw) < off+lenField {
		return nil, nil, errTruncated
	}
	n := binary.BigEndian.Uint32(raw[off:])
	off += lenField

	if n > maxPayload {
		return nil, nil, fmt.Errorf("declared payload size (%d bytes) exceeds the %d MiB limit", n, maxPayload>>20)
	}
	if uint64(len(raw)-off) < uint64(n) {
		return nil, nil, errTruncated
	}

	header := raw[:off]
	c.payload = raw[off : off+int(n)]
	return c, header, nil
}

// packInner builds bodyLen || body || padding.
func packInner(body []byte, pad bool) ([]byte, error) {
	total := lenField + len(body)
	if pad {
		total = (total + padBlock - 1) / padBlock * padBlock
	}

	inner := make([]byte, total)
	binary.BigEndian.PutUint32(inner, uint32(len(body)))
	copy(inner[lenField:], body)

	if n := total - lenField - len(body); n > 0 {
		if err := randBytes(inner[lenField+len(body):]); err != nil {
			return nil, err
		}
	}
	return inner, nil
}

// unpackInner reverses packInner and drops the padding.
func unpackInner(inner []byte) ([]byte, error) {
	if len(inner) < lenField {
		return nil, errTruncated
	}
	n := binary.BigEndian.Uint32(inner)
	if uint64(n) > uint64(len(inner)-lenField) {
		return nil, errTruncated
	}
	return inner[lenField : lenField+int(n)], nil
}
