// Package dsse shares signature input framing without sharing record or key policy.
package dsse

import (
	"crypto/sha256"
	"io"
	"strconv"
)

// Digest returns SHA-256 of the DSSE pre-authentication encoding.
func Digest(payloadType string, payload []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = io.WriteString(h, "DSSEv1 "+strconv.Itoa(len(payloadType))+" "+payloadType+" "+strconv.Itoa(len(payload))+" ")
	_, _ = h.Write(payload)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}
