package cmsaa

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/Nik-U/pbc"
)

func H0FromMessage(m string, pairing *pbc.Pairing) *pbc.Element {
	rawHash := sha256.Sum256([]byte(m))
	return pairing.NewG2().SetFromHash(rawHash[:])
}

func H1FromSplicedPks(head *pbc.Element, pks []*pbc.Element, pairing *pbc.Pairing) *pbc.Element {
	var allBytes []byte
	allBytes = append(allBytes, head.Bytes()...)
	for _, pk := range pks {
		allBytes = append(allBytes, pk.Bytes()...)
	}
	rawHash := sha512.Sum512(allBytes)
	return pairing.NewZr().SetFromHash(rawHash[:])
}
