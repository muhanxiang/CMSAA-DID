package system

import (
	"backend/model/cmsaa"
	"github.com/Nik-U/pbc"
)

type Holder struct {
	userCertificate *cmsaa.UserCertificate
	messageHash     *pbc.Element
	authMaterial    *holderAuthMaterial
	signatures      []*pbc.Element
}

type holderAuthMaterial struct {
	v *pbc.Element
	r *pbc.Element
	f *pbc.Element
	t *pbc.Element
	b *pbc.Element
	V *pbc.Element
	C *pbc.Element
	u *pbc.Element
	Y *pbc.Element
}

func (holder *Holder) Registrate(userCertificate *cmsaa.UserCertificate) {
	holder.userCertificate = userCertificate
}

func (holder *Holder) SetHash(messageHash *pbc.Element) {
	holder.messageHash = messageHash
}

func (holder *Holder) Auth1(pairing *pbc.Pairing, g1, g2 *pbc.Element) (V, C, u, Y *pbc.Element) {
	v, r, f, t, b := pairing.NewZr().Rand(), pairing.NewZr().Rand(), pairing.NewZr().Rand(), pairing.NewZr().Rand(), pairing.NewZr().Rand()
	V = pairing.NewG1().PowZn(holder.userCertificate.Certificate, v)
	C = pairing.NewG1().Mul(pairing.NewG1().PowZn(g1, holder.userCertificate.ID), pairing.NewG1().PowZn(g2, r))
	temp1 := pairing.NewGT().Pair(V, g1)
	temp1.PowZn(temp1, pairing.NewZr().Neg(f))
	temp2 := pairing.NewGT().Pair(g1, g1)
	temp2.PowZn(temp2, t)
	u = pairing.NewGT().Mul(temp1, temp2)
	temp3 := pairing.NewG1().PowZn(g1, f)
	temp4 := pairing.NewG1().PowZn(g2, b)
	Y = pairing.NewG1().Mul(temp3, temp4)
	holder.authMaterial = &holderAuthMaterial{
		v: v,
		r: r,
		f: f,
		t: t,
		b: b,
		V: V,
		C: C,
		u: u,
		Y: Y,
	}
	return V, C, u, Y
}

func (holder *Holder) Auth3(pairing *pbc.Pairing, c *pbc.Element) (_, Zid, Zv, Zr *pbc.Element) {
	Zid = pairing.NewZr().Sub(holder.authMaterial.f, pairing.NewZr().Mul(holder.userCertificate.ID, c))
	Zv = pairing.NewZr().Sub(holder.authMaterial.t, pairing.NewZr().Mul(holder.authMaterial.v, c))
	Zr = pairing.NewZr().Sub(holder.authMaterial.b, pairing.NewZr().Mul(holder.authMaterial.r, c))
	return holder.messageHash, Zid, Zv, Zr
}

func (holder *Holder) SetSig(signature *pbc.Element) {
	holder.signatures = append(holder.signatures, signature)
}
