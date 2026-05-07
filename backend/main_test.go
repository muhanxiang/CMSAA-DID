package main

import (
	"backend/config"
	"github.com/Nik-U/pbc"
	"testing"
)

func TestSimulator_NormalFlow(t *testing.T) {
	cfg := config.NewDefaultConfig()
	sim := NewSimulator(cfg)
	
	sim.Setup()
	if err := sim.Register(); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := sim.AuthRequest(); err != nil {
		t.Fatalf("AuthRequest failed: %v", err)
	}
}

func TestSimulator_ExceptionFlow_InsufficientCredentials(t *testing.T) {
	cfg := config.NewDefaultConfig()
	sim := NewSimulator(cfg)
	sim.Setup()

	// 模拟 Register，但是只收集了 t-1 个凭证
	t.Logf("开始异常测试：收集少于门限值 %d 的部分凭证", cfg.Threshold)
	
	id := sim.Holder.GenerateID(sim.Pairing.Pairing)
	
	sum := sim.Pairing.Pairing.NewZr().Add(sim.GlobalX, id)
	inv := sim.Pairing.Pairing.NewZr().Invert(sum)
	
	coeffs := make([]*pbc.Element, sim.Cfg.Threshold)
	coeffs[0] = inv
	for k := 1; k < sim.Cfg.Threshold; k++ {
		coeffs[k] = sim.Pairing.Pairing.NewZr().Rand()
	}
	
	// 故意只请求 t-1 个节点
	insufficientCount := sim.Cfg.Threshold - 1
	partialCreds := make(map[int]*pbc.Element)
	for i := 0; i < insufficientCount; i++ {
		node := sim.RANodes[i]
		z := sim.Pairing.Pairing.NewZr().SetInt32(int32(node.ID))
		share := sim.Pairing.Pairing.NewZr().Set0()
		for k := sim.Cfg.Threshold - 1; k >= 0; k-- {
			share.Mul(share, z)
			share.Add(share, coeffs[k])
		}
		partialCreds[node.ID] = node.GetPartialCredential(sim.Pairing.Pairing, sim.Pairing.G1, share)
	}
	
	// Holder 聚合
	err := sim.Holder.AggregateCredential(sim.Pairing.Pairing, partialCreds)
	if err != nil {
		// 聚合过程中可能直接抛错
		t.Logf("聚合阶段抛出错误: %v (符合预期)", err)
		return
	}
	
	// 如果聚合没有报错，由于少于门限值，生成的聚合凭证必然是错的，导致后续的 AuthRequest 验证失败
	err = sim.AuthRequest()
	if err == nil {
		t.Fatalf("异常测试失败：凭证数量不足，但验证竟然通过了！")
	}
	
	t.Logf("后续零知识验证阶段报错: %v (符合预期)", err)
}
