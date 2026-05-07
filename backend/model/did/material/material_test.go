package material

import (
	"backend/model/cmsaa"
	"encoding/hex"
	"testing"
)

func TestDataStructures(t *testing.T) {
	// 初始化配对参数
	pairingInfo := cmsaa.Generate(160, 512)
	pairing := pairingInfo.Pairing
	
	// 测试 DidDocument
	doc := &DidDocument{
		Id: "did:cmsaa:123456789",
		PublicKey: []*DidPublicKeyData{
			{
				Id:           "did:cmsaa:123456789#keys-1",
				Type:         "BilinearPairingPublicKey",
				PublicKeyHex: hex.EncodeToString(pairingInfo.G1.Bytes()),
			},
		},
	}
	docBytes, err := doc.ToJSONBytes()
	if err != nil {
		t.Fatalf("Failed to serialize DidDocument: %v", err)
	}
	t.Logf("DidDocument serialized size: %d bytes\nJSON: %s", len(docBytes), string(docBytes))

	// 测试 VerifiableClaim
	vc := &VerifiableClaim{
		Id:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Issuer: "did:cmsaa:issuer",
		CredentialSubject: &VerifiableClaimCredentialSubject{
			Id: "did:cmsaa:holder",
			CmsaaCredentials: &CmsaaCredentials{
				PublicKeyId: "did:cmsaa:issuer#keys-1",
				Type:        "BonehBoyenShortSignature",
				Value:       hex.EncodeToString(pairing.NewG1().Rand().Bytes()),
			},
		},
	}
	vcBytes, err := vc.ToJSONBytes()
	if err != nil {
		t.Fatalf("Failed to serialize VerifiableClaim: %v", err)
	}
	t.Logf("VerifiableClaim serialized size: %d bytes\nJSON: %s", len(vcBytes), string(vcBytes))

	// 测试 VerifiablePresentation
	vp := &VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Type:    []string{"VerifiablePresentation", "CmsaaZKPAuthPresentation"},
		Holder:  "did:cmsaa:holder",
		Proof: &ZKPAProof{
			Type:               "CmsaaZKP2024",
			VerificationMethod: "did:cmsaa:holder#keys-1",
			V:                  hex.EncodeToString(pairing.NewG1().Rand().Bytes()),
			C:                  hex.EncodeToString(pairing.NewG1().Rand().Bytes()),
			U:                  hex.EncodeToString(pairing.NewGT().Rand().Bytes()),
			Y:                  hex.EncodeToString(pairing.NewG1().Rand().Bytes()),
			Zid:                hex.EncodeToString(pairing.NewZr().Rand().Bytes()),
			Zv:                 hex.EncodeToString(pairing.NewZr().Rand().Bytes()),
			Zr:                 hex.EncodeToString(pairing.NewZr().Rand().Bytes()),
			Challenge:          hex.EncodeToString(pairing.NewZr().Rand().Bytes()),
		},
	}
	vpBytes, err := vp.ToJSONBytes()
	if err != nil {
		t.Fatalf("Failed to serialize VerifiablePresentation: %v", err)
	}
	t.Logf("VerifiablePresentation serialized size: %d bytes\nJSON: %s", len(vpBytes), string(vpBytes))
}
