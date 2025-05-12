package system

import (
	"backend/model/cmsaa"
	"github.com/Nik-U/pbc"
)

type Holder struct {
	userCertificate *cmsaa.UserCertificate
	messageHash     *pbc.Element
}

func (holder *Holder) Registrate(userCertificate *cmsaa.UserCertificate) {
	holder.userCertificate = userCertificate
}

func (holder *Holder) SetHash(messageHash *pbc.Element) {
	holder.messageHash = messageHash
}
