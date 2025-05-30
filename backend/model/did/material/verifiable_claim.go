package material

type VerifiableClaim struct {
	Id                string                            //VC的id
	Issuer            string                            //VC的颁发者的did
	CredentialSubject *VerifiableClaimCredentialSubject //声明的具体内容
	Proof             *VerifiableClaimProof             //签名信息
}

type VerifiableClaimCredentialSubject struct {
	Id               string            //被声明者的did
	CmsaaCredentials *CmsaaCredentials //加密后的Cmsaa凭证信息
}

type VerifiableClaimProof struct {
	Type           string //签名算法
	Creator        string //签名公钥的id
	signatureValue string //签名值
}

type CmsaaCredentials struct {
	PublicKeyId string //对应公钥id
	Type        string //加密算法类型
	Value       string //加密后的值
}
