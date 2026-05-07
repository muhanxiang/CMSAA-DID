package material

import (
	"encoding/json"
	"backend/model/cmsaa"
)

type DidDocument struct {
	Id        string              `json:"id"`
	PublicKey []*DidPublicKeyData `json:"publicKey"`
	Proof     *DidProof           `json:"proof,omitempty"`
}

type DidPublicKeyData struct {
	Id           string                    `json:"id"`
	Type         string                    `json:"type"`
	PublicKeyHex string                    `json:"publicKeyHex"`
	PublicParams *CryptographyPublicParams `json:"publicParams,omitempty"`
}

type DidProof struct {
	Type           string `json:"type"`
	Creator        string `json:"creator"`
	SignatureValue string `json:"signatureValue"`
}

type CryptographyPublicParams struct {
	Id     string         `json:"id"`
	Paring *cmsaa.Pairing `json:"-"` // 不直接序列化 PBC 对象
}

func (doc *DidDocument) ToJSONBytes() ([]byte, error) {
	return json.Marshal(doc)
}
