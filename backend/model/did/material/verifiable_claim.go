package material

type VerifiableClaim struct {
	Id                string
	Issuer            string
	CredentialSubject *VerifiableClaimCredentialSubject
	Proof             *VerifiableClaimProof
}

type VerifiableClaimCredentialSubject struct {
	Id string
}

type VerifiableClaimProof struct {
	Type           string
	Creator        string
	signatureValue string
}
