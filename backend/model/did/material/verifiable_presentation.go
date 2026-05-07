package material

import "encoding/json"

type VerifiablePresentation struct {
	Context []string   `json:"@context"`
	Type    []string   `json:"type"`
	Id      string     `json:"id,omitempty"`
	Holder  string     `json:"holder,omitempty"`
	Proof   *ZKPAProof `json:"proof,omitempty"`
}

type ZKPAProof struct {
	Type               string `json:"type"`               // e.g. "CmsaaZKP2024"
	VerificationMethod string `json:"verificationMethod"` // Reference to DID document public key
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	
	// 交互式零知识证明材料
	// 在真实的 W3C 标准中，通常会把这些编码成一个 JWS/JWT 放在 jws 字段中
	// 为了对齐论文第六章的架构，这里我们将核心代数元素直接以 Hex/Base64 形式暴露在扩展字段中
	V   string `json:"V"`
	C   string `json:"C"`
	U   string `json:"u"`
	Y   string `json:"Y"`
	Zid string `json:"Z_id"`
	Zv  string `json:"Z_v"`
	Zr  string `json:"Z_r"`
	
	// 针对交互式协议的 Challenge
	Challenge string `json:"challenge,omitempty"`
}

func (vp *VerifiablePresentation) ToJSONBytes() ([]byte, error) {
	return json.Marshal(vp)
}
