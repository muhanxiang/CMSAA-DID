package entity

import (
	"backend/model/cmsaa"
	"testing"
)

func TestDKGProtocol(t *testing.T) {
	// Initialize pairing
	pairingInfo := cmsaa.Generate(160, 512)
	pairing := pairingInfo.Pairing
	g1 := pairingInfo.G1

	n := 5
	threshold := 3

	// 1. Initialize nodes
	nodes := make([]*RANode, n)
	for i := 0; i < n; i++ {
		nodes[i] = NewRANode(i+1, n, threshold)
	}

	// 2. Generate polynomials and shares
	for i := 0; i < n; i++ {
		nodes[i].GeneratePolynomial(pairing, g1)
	}

	// 3. Distribute shares
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			// node i sends to node j
			share := nodes[i].Shares[j+1]
			commits := nodes[i].Commitments
			nodes[j].ReceiveShare(i+1, share, commits)
		}
	}

	// 4. Verify and synthesize
	for i := 0; i < n; i++ {
		err := nodes[i].VerifyAndSynthesize(pairing, g1)
		if err != nil {
			t.Fatalf("Node %d verification failed: %v", nodes[i].ID, err)
		}
	}

	// 5. Verify all nodes have the same global public key Y
	globalY := nodes[0].Y
	for i := 1; i < n; i++ {
		if !nodes[i].Y.Equals(globalY) {
			t.Fatalf("Node %d has different global Y", nodes[i].ID)
		}
	}

	// 6. Verify Lagrange interpolation can restore the main private key function
	// The main private key x = sum(a_{i,0}). We don't explicitly compute x,
	// but we can check if g1^x equals globalY.
	// We interpolate x from any 'threshold' shares (e.g., nodes 1, 2, 3)
	selectedNodes := []int{1, 2, 3}
	
	// Lagrange interpolation in Zp:
	// P(0) = sum(y_i * L_i(0))
	// L_i(0) = prod_{j!=i} (0 - x_j) / (x_i - x_j) = prod_{j!=i} x_j / (x_j - x_i)
	
	recoveredX := pairing.NewZr().Set0()
	
	for _, i := range selectedNodes {
		// Calculate L_i(0)
		li := pairing.NewZr().Set1()
		xi := pairing.NewZr().SetInt32(int32(i))
		
		for _, j := range selectedNodes {
			if i == j {
				continue
			}
			xj := pairing.NewZr().SetInt32(int32(j))
			
			// num = xj
			num := pairing.NewZr().Set(xj)
			// den = xj - xi
			den := pairing.NewZr().Sub(xj, xi)
			denInv := pairing.NewZr().Invert(den)
			
			term := pairing.NewZr().Mul(num, denInv)
			li.Mul(li, term)
		}
		
		// term = y_i * L_i(0) = node[i-1].Xi * li
		term := pairing.NewZr().Mul(nodes[i-1].Xi, li)
		recoveredX.Add(recoveredX, term)
	}

	// Verify g1^recoveredX == globalY
	testY := pairing.NewG1().PowZn(g1, recoveredX)
	if !testY.Equals(globalY) {
		t.Fatalf("Lagrange interpolation failed to recover the main secret. testY != globalY")
	}
	
	t.Logf("DKG Protocol tested successfully. All nodes agreed on Y, and Lagrange interpolation works.")
}
