package main

import (
	"backend/model/cmsaa"
	"backend/model/system/entity"
	"fmt"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func CmsaaSimulator() {
	//1.系统初始化
	pairing := cmsaa.Generate(160, 512)
	aaAmount := 10
	issuer, verifiers, holder, service := &entity.Issuer{}, make([]*entity.Verifier, aaAmount), &entity.Holder{}, &entity.Service{}
	//2.用户注册
	issuer.Init(pairing.Pairing, pairing.G1)
	for i := range verifiers {
		verifiers[i] = &entity.Verifier{}
		verifiers[i].Init(pairing.Pairing, pairing.H1)
	}
	holder.Registrate(issuer.IssueCertificate(pairing.Pairing, pairing.G1))
	service.Init("我叫牟翰翔，cmsaa构建成功")
	//3.服务请求
	holder.SetHash(service.HashMessage(pairing.Pairing))
	for _, verifier := range verifiers {
		V, C, u, Y := holder.Auth1(pairing.Pairing, pairing.G1, pairing.G2)
		verifier.SetVerifierAuthMaterial(V, C, u, Y)
		c := verifier.Auth2(pairing.Pairing)
		hm, Zid, Zv, Zr := holder.Auth3(pairing.Pairing, c)
		signature, err := verifier.VerifyAndSign(pairing.Pairing, hm, pairing.G1, pairing.G2, issuer.Y, Zid, Zv, Zr, verifiers)
		if err != nil {
			fmt.Printf("验证与签名过程失败，返回错误：%v\n", err.Error())
			return
		}
		holder.SetSig(signature)
	}
	//签名验证
	message, err := service.VerifyAndProvideService(pairing.Pairing, pairing.H1, holder.AggregateSig(pairing.Pairing), verifiers)
	if err != nil {
		fmt.Printf("验证多签名与提供服务过程失败，返回错误：%v\n", err.Error())
		return
	}
	fmt.Printf("多签名验证成功，提供消息：%v\n", message)
}

func main() {

}
