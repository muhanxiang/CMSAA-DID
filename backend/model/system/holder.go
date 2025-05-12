package system

import "backend/model/cmsaa"

type Holder struct {
	userCertificate *cmsaa.UserCertificate
}

func (holder *Holder) Registrate(userCertificate *cmsaa.UserCertificate) {
	holder.userCertificate = userCertificate
}
