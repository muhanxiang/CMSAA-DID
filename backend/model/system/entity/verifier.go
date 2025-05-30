package entity

import (
	"backend/model/cmsaa"
	"errors"
	"fmt"
	"github.com/Nik-U/pbc"
)

type Verifier struct {
	sk           *pbc.Element
	Pk           *pbc.Element
	authMaterial *verifierAuthMaterial
}

type verifierAuthMaterial struct {
	c *pbc.Element
	V *pbc.Element
	C *pbc.Element
	u *pbc.Element
	Y *pbc.Element
}

func (verifier *Verifier) Init(pairing *pbc.Pairing, h1 *pbc.Element) {
	verifier.sk = pairing.NewZr().Rand()
	verifier.Pk = pairing.NewG2().PowZn(h1, verifier.sk)
}

func (verifier *Verifier) Auth2(pairing *pbc.Pairing) *pbc.Element {
	c := pairing.NewZr().Rand()
	verifier.authMaterial.c = c
	return c
}

func (verifier *Verifier) SetVerifierAuthMaterial(V, C, u, Y *pbc.Element) {
	verifier.authMaterial = &verifierAuthMaterial{
		V: V,
		C: C,
		u: u,
		Y: Y,
	}
}

func (verifier *Verifier) VerifyAndSign(pairing *pbc.Pairing, messageHash, g1, g2, y, Zid, Zv, Zr *pbc.Element, vlist []*Verifier) (*pbc.Element, error) {
	//verify
	c, V, C, u, Y := verifier.authMaterial.c, verifier.authMaterial.V, verifier.authMaterial.C, verifier.authMaterial.u, verifier.authMaterial.Y
	temp1 := pairing.NewG1().PowZn(C, c)
	temp1.Mul(temp1, pairing.NewG1().PowZn(g2, Zr))
	temp1.Mul(temp1, pairing.NewG1().PowZn(g1, Zid))
	if !Y.Equals(temp1) {
		return nil, errors.New("验证失败，等式1不成立")
	}
	temp2 := pairing.NewGT().Pair(V, y)
	temp2.PowZn(temp2, c)
	temp3 := pairing.NewGT().Pair(V, g1)
	temp3.PowZn(temp3, pairing.NewZr().Neg(Zid))
	temp4 := pairing.NewGT().Pair(g1, g1)
	temp4.PowZn(temp4, Zv)
	temp2.Mul(temp2, temp3)
	temp2.Mul(temp2, temp4)
	if !u.Equals(temp2) {
		fmt.Println(u)
		fmt.Println(temp2)
		return nil, errors.New("验证失败，等式2不成立")
	}
	//sign
	pkList := make([]*pbc.Element, len(vlist))
	for i, v := range vlist {
		pkList[i] = v.Pk
	}
	ai := cmsaa.H1FromSplicedPks(verifier.Pk, pkList, pairing)
	si := pairing.NewG2().Set(messageHash)
	si.PowZn(si, pairing.NewZr().Mul(ai, verifier.sk))
	return si, nil
}
