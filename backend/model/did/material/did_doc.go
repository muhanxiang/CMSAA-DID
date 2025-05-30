package material

import "backend/model/cmsaa"

type DidDocument struct {
	Id        string              //did文档id
	PublicKey []*DidPublicKeyData //持有的公钥信息
	Proof     *DidProof           //签名信息
}

type DidPublicKeyData struct {
	Id           string                    //公钥id
	Type         string                    //密钥算法
	PublicKeyHex string                    //公钥的十六进制编码表示
	PublicParams *CryptographyPublicParams //算法公共参数
}

type DidProof struct {
	Type           string //签名算法
	Creator        string //签名公钥的id
	signatureValue string //签名值
}

type CryptographyPublicParams struct {
	Id     string
	Paring *cmsaa.Pairing
}
