package system

import (
	"backend/model/cmsaa"
	"github.com/Nik-U/pbc"
)

type Issuer struct {
	x *pbc.Element
	Y *pbc.Element
}

func (issuer *Issuer) Init(pairing *pbc.Pairing, g1 *pbc.Element) {
	issuer.x = pairing.NewZr().Rand()
	issuer.Y = pairing.NewG1().PowZn(g1, issuer.x)
}

func (issuer *Issuer) IssueCertificate(pairing *pbc.Pairing, g1 *pbc.Element) cmsaa.UserCertificate {
	id := pairing.NewZr().Rand()
	sum := pairing.NewZr().Add(issuer.x, id)
	inv := pairing.NewZr().Invert(sum)
	certificate := pairing.NewG1().PowZn(g1, inv)
	return cmsaa.UserCertificate{
		ID:          id,
		Certificate: certificate,
	}
}
