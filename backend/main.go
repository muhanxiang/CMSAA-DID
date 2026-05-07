package main

import (
	"backend/config"
	"backend/logger"
	"backend/model/cmsaa"
	"backend/model/did/material"
	"backend/model/system/entity"
	"encoding/hex"
	"github.com/Nik-U/pbc"
)

// Simulator 控制协议生命周期的执行流
type Simulator struct {
	Cfg       *config.Config
	Pairing   *cmsaa.Pairing
	GlobalX   *pbc.Element
	RANodes   []*entity.RANode
	Verifiers []*entity.Verifier
	Holder    *entity.Holder
	Service   *entity.Service
}

// NewSimulator 创建一个新的模拟器实例
func NewSimulator(cfg *config.Config) *Simulator {
	return &Simulator{
		Cfg:       cfg,
		RANodes:   make([]*entity.RANode, cfg.RaCount),
		Verifiers: make([]*entity.Verifier, cfg.VerifierCount),
		Holder:    &entity.Holder{},
		Service:   &entity.Service{},
	}
}

// Setup 阶段 1与2.1：系统参数生成、实体初始化与 DKG
func (s *Simulator) Setup() {
	logger.Step("1. Setup: 系统参数与实体初始化开始")
	s.Pairing = cmsaa.Generate(s.Cfg.Rbits, s.Cfg.Qbits)
	logger.Info("双线性配对参数生成完毕 (Rbits: %d, Qbits: %d)", s.Cfg.Rbits, s.Cfg.Qbits)

	// DKG 流程
	logger.Step("2.1 DKG: 分布式密钥生成开始")
	for i := 0; i < s.Cfg.RaCount; i++ {
		s.RANodes[i] = entity.NewRANode(i+1, s.Cfg.RaCount, s.Cfg.Threshold)
		s.RANodes[i].GeneratePolynomial(s.Pairing.Pairing, s.Pairing.G1)
	}

	// 节点间分发 Share 与 Commitments
	for i := 0; i < s.Cfg.RaCount; i++ {
		for j := 0; j < s.Cfg.RaCount; j++ {
			s.RANodes[j].ReceiveShare(i+1, s.RANodes[i].Shares[j+1], s.RANodes[i].Commitments)
		}
	}

	// 验证分片并合成公私钥分片
	for i := 0; i < s.Cfg.RaCount; i++ {
		if err := s.RANodes[i].VerifyAndSynthesize(s.Pairing.Pairing, s.Pairing.G1); err != nil {
			logger.Error("RANode %d DKG 验证失败: %v", i+1, err)
			return
		}
	}
	
	// 提取全局主私钥 x 以用于模拟器后续步骤
	// 注意：真实场景中，没有任何单点知道 x，这里仅为了复现协议流程并模拟 MPC
	s.GlobalX = s.Pairing.Pairing.NewZr().Set0()
	// 使用前 Threshold 个节点来恢复 x
	for i := 0; i < s.Cfg.Threshold; i++ {
		li := s.Pairing.Pairing.NewZr().Set1()
		xi := s.Pairing.Pairing.NewZr().SetInt32(int32(s.RANodes[i].ID))
		for j := 0; j < s.Cfg.Threshold; j++ {
			if i == j {
				continue
			}
			xj := s.Pairing.Pairing.NewZr().SetInt32(int32(s.RANodes[j].ID))
			num := s.Pairing.Pairing.NewZr().Set(xj)
			den := s.Pairing.Pairing.NewZr().Sub(xj, xi)
			denInv := s.Pairing.Pairing.NewZr().Invert(den)
			li.Mul(li, s.Pairing.Pairing.NewZr().Mul(num, denInv))
		}
		term := s.Pairing.Pairing.NewZr().Mul(s.RANodes[i].Xi, li)
		s.GlobalX.Add(s.GlobalX, term)
	}

	logger.Success("DKG 成功！%d 个 RA 节点共同生成了主公钥，门限值为 %d", s.Cfg.RaCount, s.Cfg.Threshold)
	logger.Info("主公钥 Y (截断): %x...", s.RANodes[0].Y.Bytes()[:10])

	for i := range s.Verifiers {
		s.Verifiers[i] = &entity.Verifier{}
		s.Verifiers[i].Init(s.Pairing.Pairing, s.Pairing.H1)
	}
	s.Service.Init("Service Access Granted: Authorization Verified")
	logger.Info("成功初始化 %d 个 Verifier (授权机构)", s.Cfg.VerifierCount)
}

// Register 阶段 2.2：分布式用户注册与凭证颁发
func (s *Simulator) Register() error {
	logger.Step("2.2 Register: 用户向 RA 节点请求凭证开始")
	// 1. Holder 生成自己的身份 ID
	id := s.Holder.GenerateID(s.Pairing.Pairing)
	
	// 2. 模拟 RA 节点的 MPC 求逆过程
	// 我们需要构造一个 t-1 阶多项式 P(z)，使得 P(0) = 1/(x+id)
	sum := s.Pairing.Pairing.NewZr().Add(s.GlobalX, id)
	inv := s.Pairing.Pairing.NewZr().Invert(sum)
	
	coeffs := make([]*pbc.Element, s.Cfg.Threshold)
	coeffs[0] = inv
	for k := 1; k < s.Cfg.Threshold; k++ {
		coeffs[k] = s.Pairing.Pairing.NewZr().Rand()
	}
	
	// 3. 各个 RA 节点利用其 MPC 分片签发部分凭证
	partialCreds := make(map[int]*pbc.Element)
	
	// 仅请求前 t 个节点 (满足门限)
	for i := 0; i < s.Cfg.Threshold; i++ {
		node := s.RANodes[i]
		
		// 计算多项式 P(node.ID) 作为其 MPC 分片
		z := s.Pairing.Pairing.NewZr().SetInt32(int32(node.ID))
		share := s.Pairing.Pairing.NewZr().Set0()
		for k := s.Cfg.Threshold - 1; k >= 0; k-- {
			share.Mul(share, z)
			share.Add(share, coeffs[k])
		}
		
		// 节点签发部分凭证
		partialCred := node.GetPartialCredential(s.Pairing.Pairing, s.Pairing.G1, share)
		partialCreds[node.ID] = partialCred
	}
	logger.Info("用户成功收集到 %d 个 RA 节点的部分凭证", s.Cfg.Threshold)

	// 4. Holder 聚合部分凭证
	if err := s.Holder.AggregateCredential(s.Pairing.Pairing, partialCreds); err != nil {
		logger.Error("凭证聚合失败: %v", err)
		return err
	}

	// 5. DID 兼容：封装为 VerifiableClaim
	vc := &material.VerifiableClaim{
		Id:     "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		Issuer: "did:cmsaa:issuer-committee",
		CredentialSubject: &material.VerifiableClaimCredentialSubject{
			Id: "did:cmsaa:holder",
			CmsaaCredentials: &material.CmsaaCredentials{
				PublicKeyId: "did:cmsaa:issuer-committee#keys-1",
				Type:        "BonehBoyenShortSignature",
				Value:       hex.EncodeToString(s.Holder.GetCertificate().Bytes()),
			},
		},
	}
	vcBytes, _ := vc.ToJSONBytes()
	logger.Info("用户分配到的随机身份标识 ID (截断): %x...", id.Bytes()[:10])
	logger.Info("Holder 成功聚合 VC (VerifiableClaim)，序列化大小: %d bytes", len(vcBytes))
	
	logger.Success("分布式凭证聚合成功，完成零知识认证材料准备")
	return nil
}

// AuthRequest 阶段 3：服务请求与交互式零知识认证
func (s *Simulator) AuthRequest() error {
	logger.Step("3. AuthRequest: 交互式零知识认证与部分签名获取开始")
	s.Holder.SetHash(s.Service.HashMessage(s.Pairing.Pairing))
	
	vpSizeTotal := 0
	
	for i, verifier := range s.Verifiers {
		V, C, u, Y := s.Holder.Auth1(s.Pairing.Pairing, s.Pairing.G1, s.Pairing.G2)
		verifier.SetVerifierAuthMaterial(V, C, u, Y)
		c := verifier.Auth2(s.Pairing.Pairing)
		hm, Zid, Zv, Zr := s.Holder.Auth3(s.Pairing.Pairing, c)
		
		// 封装为 VerifiablePresentation 以模拟真实网络请求
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
		vpSizeTotal += len(vpBytes)
		
		signature, err := verifier.VerifyAndSign(s.Pairing.Pairing, hm, s.Pairing.G1, s.Pairing.G2, s.RANodes[0].Y, Zid, Zv, Zr, s.Verifiers)
		if err != nil {
			logger.Error("Verifier %d 验证与签名过程失败：%v", i, err.Error())
			return err
		}
		s.Holder.SetSig(signature)
	}
	logger.Info("Holder 成功向 %d 个 Verifier 提交 VP，单个 VP 平均大小: %d bytes", s.Cfg.VerifierCount, vpSizeTotal/s.Cfg.VerifierCount)
	logger.Success("用户成功通过 %d 个 Verifier 的认证，并收集到部分签名", s.Cfg.VerifierCount)
	return nil
}

// ServiceVerify 阶段 4：签名聚合与服务提供侧验证
func (s *Simulator) ServiceVerify() {
	logger.Step("4. ServiceVerify: 签名聚合与服务验证开始")
	aggSig := s.Holder.AggregateSig(s.Pairing.Pairing)
	logger.Info("Holder 成功聚合了 %d 个 Verifier 的部分签名", s.Cfg.VerifierCount)
	logger.Info("聚合多重签名 \u03c3 (截断): %x...", aggSig.Bytes()[:10])
	
	message, err := s.Service.VerifyAndProvideService(s.Pairing.Pairing, s.Pairing.H1, aggSig, s.Verifiers)
	if err != nil {
		logger.Error("SP 验证多重签名与提供服务过程失败：%v", err.Error())
		return
	}
	logger.Success("多签名验证成功！服务提供者(SP)释放消息：[%v]", message)
}

// Run 执行整个协议生命周期
func (s *Simulator) Run() {
	s.Setup()
	if err := s.Register(); err != nil {
		return
	}
	if err := s.AuthRequest(); err != nil {
		return
	}
	s.ServiceVerify()
}

func main() {
	// 加载默认配置
	cfg := config.NewDefaultConfig()
	
	logger.Info("CMSAA-DID 协议模拟器启动")
	logger.Info("当前系统配置: RA节点数=%d, 门限值=%d, 授权机构数(AA)=%d", cfg.RaCount, cfg.Threshold, cfg.VerifierCount)
	
	sim := NewSimulator(cfg)
	sim.Run()
}
