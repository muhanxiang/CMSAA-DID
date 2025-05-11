package cmsaa

import "github.com/Nik-U/pbc"

type Pairing struct {
	pairing *pbc.Pairing
	G1      *pbc.Element
	G2      *pbc.Element
	H1      *pbc.Element
	H2      *pbc.Element
	//p就是r 用newZr().rand()可以初始化一个Zp上的随机数
}

func Generate(rbits, qbits uint32) *Pairing {
	params := pbc.GenerateA(rbits, qbits)
	pairing := pbc.NewPairing(params)
	return &Pairing{
		pairing: pairing,
		G1:      pairing.NewG1().Rand(),
		G2:      pairing.NewG1().Rand(),
		H1:      pairing.NewG2().Rand(),
		H2:      pairing.NewG2().Rand(),
	}
}

func (pairing *Pairing) Pair(e1, e2 *pbc.Element) *pbc.Element {
	return pairing.pairing.NewGT().Pair(e1, e2)
}
