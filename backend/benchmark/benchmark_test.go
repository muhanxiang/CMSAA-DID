package benchmark

import (
	"backend/model/cmsaa"
	"backend/model/did/material"
	"backend/model/system/entity"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// setupEnv 初始化基准测试的基础环境
func setupEnv(verifierCount int) (*cmsaa.Pairing, *entity.Holder, []*entity.Verifier, *entity.Service, *entity.RANode) {
	pairingInfo := cmsaa.Generate(160, 512)
	holder := &entity.Holder{}

	raNode := entity.NewRANode(1, 1, 1)
	raNode.GeneratePolynomial(pairingInfo.Pairing, pairingInfo.G1)
	raNode.ReceiveShare(1, raNode.Shares[1], raNode.Commitments)
	raNode.VerifyAndSynthesize(pairingInfo.Pairing, pairingInfo.G1)

	id := holder.GenerateID(pairingInfo.Pairing)
	sum := pairingInfo.Pairing.NewZr().Add(raNode.Xi, id)
	inv := pairingInfo.Pairing.NewZr().Invert(sum)
	cert := pairingInfo.Pairing.NewG1().PowZn(pairingInfo.G1, inv)
	holder.Registrate(&cmsaa.UserCertificate{ID: id, Certificate: cert})

	verifiers := make([]*entity.Verifier, verifierCount)
	for i := range verifiers {
		verifiers[i] = &entity.Verifier{}
		verifiers[i].Init(pairingInfo.Pairing, pairingInfo.H1)
	}

	service := &entity.Service{}
	service.Init("Test Message")
	holder.SetHash(service.HashMessage(pairingInfo.Pairing))

	return pairingInfo, holder, verifiers, service, raNode
}

// 实验1：测试随着授权机构(Verifier)数量增加，服务提供者(SP)验证聚合签名的耗时
func TestExperiment1_SPVerifyTimeByVerifierCount(t *testing.T) {
	counts := []int{5, 10, 20, 50, 100}
	fmt.Println("=== 实验1: SP 验证多重签名耗时 vs 授权机构数量 ===")
	for _, count := range counts {
		pairingInfo, holder, verifiers, service, raNode := setupEnv(count)

		// 提前完成认证并收集签名
		for _, verifier := range verifiers {
			V, C, u, Y := holder.Auth1(pairingInfo.Pairing, pairingInfo.G1, pairingInfo.G2)
			verifier.SetVerifierAuthMaterial(V, C, u, Y)
			c := verifier.Auth2(pairingInfo.Pairing)
			hm, Zid, Zv, Zr := holder.Auth3(pairingInfo.Pairing, c)
			signature, _ := verifier.VerifyAndSign(pairingInfo.Pairing, hm, pairingInfo.G1, pairingInfo.G2, raNode.Y, Zid, Zv, Zr, verifiers)
			holder.SetSig(signature)
		}
		aggSig := holder.AggregateSig(pairingInfo.Pairing)

		// 测量 SP 的验证耗时
		start := time.Now()
		_, err := service.VerifyAndProvideService(pairingInfo.Pairing, pairingInfo.H1, aggSig, verifiers)
		duration := time.Since(start)

		if err != nil {
			t.Fatalf("验证失败: %v", err)
		}
		fmt.Printf("授权机构数量: %3d | SP 验证耗时: %v\n", count, duration)
	}
}

// 实验2：测试零知识证明交互中 Holder 生成 VP 证明材料的计算开销
func BenchmarkHolderGenerateZKPProof(b *testing.B) {
	pairingInfo, holder, _, _, _ := setupEnv(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 测量 Auth1 (包含主要的群运算：生成 V, C, u, Y)
		holder.Auth1(pairingInfo.Pairing, pairingInfo.G1, pairingInfo.G2)
	}
}

// 实验3：测试单个 Verifier 验证 ZKP 并生成部分签名的计算开销
func BenchmarkVerifierVerifyAndSign(b *testing.B) {
	pairingInfo, holder, verifiers, _, raNode := setupEnv(1)
	verifier := verifiers[0]

	V, C, u, Y := holder.Auth1(pairingInfo.Pairing, pairingInfo.G1, pairingInfo.G2)
	verifier.SetVerifierAuthMaterial(V, C, u, Y)
	c := verifier.Auth2(pairingInfo.Pairing)
	hm, Zid, Zv, Zr := holder.Auth3(pairingInfo.Pairing, c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifyAndSign(pairingInfo.Pairing, hm, pairingInfo.G1, pairingInfo.G2, raNode.Y, Zid, Zv, Zr, verifiers)
	}
}

// 实验4：空间开销测量 (序列化数据包大小)
func TestExperiment4_CommunicationOverhead(t *testing.T) {
	pairingInfo, holder, _, _, _ := setupEnv(1)

	fmt.Println("\n=== 实验4: 通信与存储开销 (基于 JSON 序列化) ===")

	// 1. DID Document 大小
	doc := &material.DidDocument{
		Id: "did:cmsaa:123456789",
		PublicKey: []*material.DidPublicKeyData{
			{
				Id:           "did:cmsaa:123456789#keys-1",
				Type:         "BilinearPairingPublicKey",
				PublicKeyHex: hex.EncodeToString(pairingInfo.G1.Bytes()),
			},
		},
	}
	docBytes, _ := doc.ToJSONBytes()
	fmt.Printf("DID Document 基础大小: %d bytes\n", len(docBytes))

	// 2. VC 大小
	vc := &material.VerifiableClaim{
		Id:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Issuer: "did:cmsaa:issuer",
		CredentialSubject: &material.VerifiableClaimCredentialSubject{
			Id: "did:cmsaa:holder",
			CmsaaCredentials: &material.CmsaaCredentials{
				PublicKeyId: "did:cmsaa:issuer#keys-1",
				Type:        "BonehBoyenShortSignature",
				Value:       hex.EncodeToString(holder.GetCertificate().Bytes()),
			},
		},
	}
	vcBytes, _ := vc.ToJSONBytes()
	fmt.Printf("Verifiable Claim (包含匿名凭证) 大小: %d bytes\n", len(vcBytes))

	// 3. VP 大小 (ZKP 证明包)
	V, C, u, Y := holder.Auth1(pairingInfo.Pairing, pairingInfo.G1, pairingInfo.G2)
	c := pairingInfo.Pairing.NewZr().Rand()
	_, Zid, Zv, Zr := holder.Auth3(pairingInfo.Pairing, c)

	vp := &material.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Type:    []string{"VerifiablePresentation", "CmsaaZKPAuthPresentation"},
		Holder:  "did:cmsaa:holder",
		Proof: &material.ZKPAProof{
			Type:               "CmsaaZKP2024",
			VerificationMethod: "did:cmsaa:holder#keys-1",
			V:                  hex.EncodeToString(V.Bytes()),
			C:                  hex.EncodeToString(C.Bytes()),
			U:                  hex.EncodeToString(u.Bytes()),
			Y:                  hex.EncodeToString(Y.Bytes()),
			Zid:                hex.EncodeToString(Zid.Bytes()),
			Zv:                 hex.EncodeToString(Zv.Bytes()),
			Zr:                 hex.EncodeToString(Zr.Bytes()),
			Challenge:          hex.EncodeToString(c.Bytes()),
		},
	}
	vpBytes, _ := vp.ToJSONBytes()
	fmt.Printf("Verifiable Presentation (ZKP 认证请求包) 大小: %d bytes\n", len(vpBytes))
	
	// 4. 多重签名结果大小
	aggSig := pairingInfo.Pairing.NewG2().Rand()
	fmt.Printf("聚合多重签名 \u03c3 (基于 G2 群元素) 裸数据大小: %d bytes\n", len(aggSig.Bytes()))
}
