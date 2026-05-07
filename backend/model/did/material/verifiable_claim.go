package material

import "encoding/json"

type VerifiableClaim struct {
	Id                string                            `json:"id"`
	Issuer            string                            `json:"issuer"`
	CredentialSubject *VerifiableClaimCredentialSubject `json:"credentialSubject"`
	Proof             *VerifiableClaimProof             `json:"proof,omitempty"`
}

type VerifiableClaimCredentialSubject struct {
	Id               string            `json:"id"`
	CmsaaCredentials *CmsaaCredentials `json:"cmsaaCredentials"`
}

type VerifiableClaimProof struct {
	Type           string `json:"type"`
	Creator        string `json:"creator"`
	SignatureValue string `json:"signatureValue"`
}

type CmsaaCredentials struct {
	PublicKeyId string `json:"publicKeyId"`
	Type        string `json:"type"`
	Value       string `json:"value"` // 例如：PBC 元素的 Bytes() 的 Base64 或 Hex
}

func (vc *VerifiableClaim) ToJSONBytes() ([]byte, error) {
	return json.Marshal(vc)
}
