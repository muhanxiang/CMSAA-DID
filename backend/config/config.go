package config

// Config 存储系统运行的全局参数
type Config struct {
	Rbits         uint32 // 双线性配对安全参数 Rbits
	Qbits         uint32 // 双线性配对安全参数 Qbits
	RaCount       int    // 注册机构(RA)节点总数
	Threshold     int    // DKG 门限值 (t)
	VerifierCount int    // 授权机构(AA/Verifier)数量
}

// NewDefaultConfig 返回默认配置，严格对齐论文中的实验设定
func NewDefaultConfig() *Config {
	return &Config{
		Rbits:         160,
		Qbits:         512,
		RaCount:       5,  // 默认5个RA节点
		Threshold:     3,  // 门限为3 (需要至少3个节点才能生成凭证)
		VerifierCount: 10, // 默认10个授权机构(AA)参与多方授权
	}
}
