package main

import (
	"backend/model/cmsaa"
	"backend/model/system"
	"fmt"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	//1.系统初始化
	pairing := cmsaa.Generate(160, 512)
	aaAmount := 10
	issuer, verifiers, holder, service := &system.Issuer{}, make([]*system.Verifier, aaAmount), &system.Holder{}, &system.Service{}
	//2.用户注册
	issuer.Init(pairing.Pairing, pairing.G1)
	for i := range verifiers {
		verifiers[i] = &system.Verifier{}
		verifiers[i].Init(pairing.Pairing, pairing.H1)
	}
	holder.Registrate(issuer.IssueCertificate(pairing.Pairing, pairing.G1))
	service.Init("能最后得到我吗勇士?")
	//3.服务请求
	holder.SetHash(service.HashMessage(pairing.Pairing))
	for _, verifier := range verifiers {
		V, C, u, Y := holder.Auth1(pairing.Pairing, pairing.G1, pairing.G2)
		verifier.SetVerifierAuthMaterial(V, C, u, Y)
		c := verifier.Auth2(pairing.Pairing)
		hm, Zid, Zv, Zr := holder.Auth3(pairing.Pairing, c)
		_, err := verifier.Verify(pairing.Pairing, hm, pairing.G1, pairing.G2, issuer.Y, Zid, Zv, Zr)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("验证成功")
		}
	}
}
