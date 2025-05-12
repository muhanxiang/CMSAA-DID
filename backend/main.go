package main

import (
	"backend/model/cmsaa"
	"backend/model/system"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	pairing := cmsaa.Generate(160, 512)
	aaAmount := 10
	issuer, verifiers, holder := &system.Issuer{}, make([]*system.Verifier, aaAmount), &system.Holder{}
	issuer.Init(pairing.Pairing, pairing.G1)
	for _, verifier := range verifiers {
		verifier.Init(pairing.Pairing, pairing.H1)
	}
	holder.Registrate(issuer.IssueCertificate(pairing.Pairing, pairing.G1))
}
