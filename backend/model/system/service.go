package system

import (
	"backend/model/cmsaa"
	"errors"
	"github.com/Nik-U/pbc"
)

type Service struct {
	message     string
	messageHash *pbc.Element
}

func (service *Service) Init(message string) {
	service.message = message
}

func (service *Service) HashMessage(pairing *pbc.Pairing) *pbc.Element {
	service.messageHash = cmsaa.H0FromMessage(service.message, pairing)
	return service.messageHash
}

func (service *Service) VerifyAndProvideService(pairing *pbc.Pairing, h1, multiSig *pbc.Element, vlist []*Verifier) (string, error) {
	//verify
	apk := pairing.NewG2().Set1()
	pkList := make([]*pbc.Element, len(vlist))
	for i, v := range vlist {
		pkList[i] = v.Pk
	}
	for _, verifier := range vlist {
		ai := cmsaa.H1FromSplicedPks(verifier.Pk, pkList, pairing)
		apk.Mul(apk, pairing.NewG2().PowZn(verifier.Pk, ai))
	}
	temp := pairing.NewGT().Pair(multiSig, pairing.NewG2().Invert(h1))
	temp.Mul(temp, pairing.NewGT().Pair(service.messageHash, apk))
	if !temp.Equals(pairing.NewGT().Set1()) {
		return "", errors.New("验证失败，等式不成立")
	}
	//provide
	return service.message, nil
}
