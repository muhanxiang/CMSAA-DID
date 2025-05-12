package system

import "github.com/Nik-U/pbc"

type Verifier struct {
	sk *pbc.Element
	Pk *pbc.Element
}

func (verifier *Verifier) Init(pairing *pbc.Pairing, h1 *pbc.Element) {
	verifier.sk = pairing.NewZr().Rand()
	verifier.Pk = pairing.NewG2().PowZn(h1, verifier.sk)
}
