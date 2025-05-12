package system

import (
	"backend/model/cmsaa"
	"github.com/Nik-U/pbc"
)

type Service struct {
	message string
}

func (service *Service) Init(message string) {
	service.message = message
}

func (service *Service) HashMessage(pairing *pbc.Pairing) *pbc.Element {
	return cmsaa.H0FromMessage(service.message, pairing)
}
