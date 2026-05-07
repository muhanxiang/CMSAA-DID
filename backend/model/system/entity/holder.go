package entity

import (
	"backend/model/cmsaa"
	"github.com/Nik-U/pbc"
)

type Holder struct {
	userCertificate *cmsaa.UserCertificate
	messageHash     *pbc.Element
	authMaterial    *holderAuthMaterial
	signatures      []*pbc.Element
	multiSignature  *pbc.Element
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

// GenerateID 为分布式注册生成一个随机 ID
func (holder *Holder) GenerateID(pairing *pbc.Pairing) *pbc.Element {
	id := pairing.NewZr().Rand()
	// 暂存 ID，以便后续聚合时封装成完整证书
	if holder.userCertificate == nil {
		holder.userCertificate = &cmsaa.UserCertificate{ID: id}
	} else {
		holder.userCertificate.ID = id
	}
	return id
}

// AggregateCredential 使用拉格朗日插值聚合部分凭证
func (holder *Holder) AggregateCredential(pairing *pbc.Pairing, partialCreds map[int]*pbc.Element) error {
	if len(partialCreds) == 0 {
		return nil
	}
	
	// 拉格朗日插值聚合: C = prod C_i^{L_i(0)}
	aggregatedCert := pairing.NewG1().Set1()
	
	// 提取参与的节点 ID
	var nodeIDs []int
	for id := range partialCreds {
		nodeIDs = append(nodeIDs, id)
	}

	for _, i := range nodeIDs {
		// 计算拉格朗日系数 L_i(0)
		li := pairing.NewZr().Set1()
		xi := pairing.NewZr().SetInt32(int32(i))
		
		for _, j := range nodeIDs {
			if i == j {
				continue
			}
			xj := pairing.NewZr().SetInt32(int32(j))
			num := pairing.NewZr().Set(xj)
			den := pairing.NewZr().Sub(xj, xi)
			denInv := pairing.NewZr().Invert(den)
			term := pairing.NewZr().Mul(num, denInv)
			li.Mul(li, term)
		}
		
		// term = C_i^{L_i(0)}
		part := partialCreds[i]
		term := pairing.NewG1().PowZn(part, li)
		aggregatedCert.Mul(aggregatedCert, term)
	}
	
	holder.userCertificate.Certificate = aggregatedCert
	return nil
}

func (holder *Holder) GetCertificate() *pbc.Element {
	if holder.userCertificate != nil {
		return holder.userCertificate.Certificate
	}
	return nil
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

func (holder *Holder) AggregateSig(pairing *pbc.Pairing) *pbc.Element {
	holder.multiSignature = pairing.NewG2().Set1()
	for _, sig := range holder.signatures {
		holder.multiSignature.Mul(holder.multiSignature, sig)
	}
	return holder.multiSignature
}
