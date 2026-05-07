package entity

import (
	"fmt"
	"github.com/Nik-U/pbc"
)

type RANode struct {
	ID        int
	N         int // Total RA nodes
	T         int // Threshold
	
	coeffs    []*pbc.Element // Polynomial coefficients a_{i,0}, ..., a_{i,t-1}
	Shares    map[int]*pbc.Element // Shares to send: s_{i->j}
	Commitments []*pbc.Element // C_{i,k} = g1^{a_{i,k}}

	// Received data
	ReceivedShares map[int]*pbc.Element // s_{k->ID}
	ReceivedCommits map[int][]*pbc.Element // C_{k, ...}

	// Final results
	Xi *pbc.Element // Private key share
	Y  *pbc.Element // Global main public key
}

func NewRANode(id, n, t int) *RANode {
	return &RANode{
		ID: id,
		N:  n,
		T:  t,
		Shares: make(map[int]*pbc.Element),
		ReceivedShares: make(map[int]*pbc.Element),
		ReceivedCommits: make(map[int][]*pbc.Element),
	}
}

// GeneratePolynomial 1. Generate local polynomial and commitments
func (node *RANode) GeneratePolynomial(pairing *pbc.Pairing, g1 *pbc.Element) {
	node.coeffs = make([]*pbc.Element, node.T)
	node.Commitments = make([]*pbc.Element, node.T)

	for k := 0; k < node.T; k++ {
		node.coeffs[k] = pairing.NewZr().Rand()
		node.Commitments[k] = pairing.NewG1().PowZn(g1, node.coeffs[k])
	}

	// Generate shares for all j from 1 to N
	for j := 1; j <= node.N; j++ {
		// evaluate f_i(j)
		z := pairing.NewZr().SetInt32(int32(j))
		share := pairing.NewZr().Set0()
		
		for k := node.T - 1; k >= 0; k-- {
			share.Mul(share, z)
			share.Add(share, node.coeffs[k])
		}
		node.Shares[j] = share
	}
}

// ReceiveShare 2. Receive share and commitments from another node
func (node *RANode) ReceiveShare(fromID int, share *pbc.Element, commitments []*pbc.Element) {
	node.ReceivedShares[fromID] = share
	node.ReceivedCommits[fromID] = commitments
}

// VerifyAndSynthesize 3. Verify shares and synthesize keys
func (node *RANode) VerifyAndSynthesize(pairing *pbc.Pairing, g1 *pbc.Element) error {
	node.Xi = pairing.NewZr().Set0()
	
	for i := 1; i <= node.N; i++ {
		share := node.ReceivedShares[i]
		commits := node.ReceivedCommits[i]
		
		// Verify g1^share == prod(commits[k]^(ID^k))
		lhs := pairing.NewG1().PowZn(g1, share)
		rhs := pairing.NewG1().Set1()
		
		jVal := pairing.NewZr().SetInt32(int32(node.ID))
		for k := 0; k < node.T; k++ {
			kVal := pairing.NewZr().SetInt32(int32(k))
			jPowK := pairing.NewZr().PowZn(jVal, kVal)
			term := pairing.NewG1().PowZn(commits[k], jPowK)
			rhs.Mul(rhs, term)
		}
		
		if !lhs.Equals(rhs) {
			return fmt.Errorf("node %d failed to verify share from node %d", node.ID, i)
		}
		
		// Synthesize Xi
		node.Xi.Add(node.Xi, share)
	}
	
	// Synthesize Y (Global main public key)
	node.Y = pairing.NewG1().Set1()
	for i := 1; i <= node.N; i++ {
		node.Y.Mul(node.Y, node.ReceivedCommits[i][0])
	}
	
	return nil
}

// GetPartialCredential 节点使用由 MPC 生成的求逆分片签发部分凭证
// 在实际协议中，节点利用私钥分片 xi 和交互式 MPC 协议共同计算出 1/(x+id) 的分片
// 这里通过 invShare 模拟该 MPC 阶段的结果，节点返回部分凭证
func (node *RANode) GetPartialCredential(pairing *pbc.Pairing, g1 *pbc.Element, invShare *pbc.Element) *pbc.Element {
	// A_i = g1^{invShare}
	return pairing.NewG1().PowZn(g1, invShare)
}
