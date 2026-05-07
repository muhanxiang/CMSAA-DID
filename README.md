# CMSAA-DID

一种基于去中心化身份 (DID) 的具有交互式匿名认证的多方授权方案实现。

## 项目简介

本项目旨在复现大论文《一种具有隐私保护的多方授权系统的设计与实现》中的核心密码学协议与业务流程。
- **论文链接**：[https://www.chinaaet.com/article/3000176882](https://www.chinaaet.com/article/3000176882)
- **所属期刊**：《电子技术应用》 (ChinaAET)
- **作者**：牟翰翔 等

通过结合 **W3C DID/VC 架构**、**Boneh-Drijvers-Neven 紧凑多重签名** 以及 **交互式零知识集合成员证明**，本系统能够在保证用户绝对匿名性的同时，实现安全、可靠的多方授权。

### 核心特性
- **完全去中心化发证 (DKG)**：废除单点 Issuer，通过 Shamir 秘密共享机制由多个 RA 节点分布式协同生成并签发用户凭证。
- **强隐私匿名认证 (ZKP)**：用户利用拉格朗日插值在本地聚合凭证后，通过零知识证明 (Zero-Knowledge Proofs) 盲化身份向授权机构请求授权，全过程不暴露真实身份。
- **高并发紧凑多方授权 (MSP)**：授权机构生成的多重签名具备防“流氓密钥攻击”特性，聚合后的签名尺寸极小，SP（服务提供者）验证高效。
- **标准 DID 数据结构兼容**：底层的密码学参数与协议执行结果可完美封装并序列化为 W3C 标准的 `DidDocument`, `VerifiableClaim`, `VerifiablePresentation` JSON 结构。

## 项目结构

```
.
├── backend
│   ├── benchmark/           # 针对大论文第六章的性能测量基准测试
│   ├── config/              # 全局核心配置参数（Rbits, Qbits, RaCount, Threshold, VerifierCount 等）
│   ├── logger/              # 格式化控制台输出
│   ├── model
│   │   ├── cmsaa/           # 核心密码学原语，基于 PBC 库封装双线性群配对与哈希函数
│   │   ├── did/material/    # W3C DID 兼容的数据结构定义与 JSON 序列化
│   │   └── system/entity/   # 协议参与实体 (Holder, RANode, Verifier, Service)
│   ├── main.go              # 主流程模拟器入口
│   └── main_test.go         # 异常流测试用例
└── essay/                   # 相关大纲与文稿资料
```

## 环境依赖

本项目基于 Golang 与 C 语言的 PBC（Pairing-Based Cryptography）密码学库开发。

1. **安装 Go (>=1.18)**
2. **安装 PBC Library 与 GMP Library** (底层大数与双线性配对计算依赖)
   - macOS: `brew install pbc gmp`
   - Linux: `sudo apt-get install libpbc-dev libgmp-dev`

## 运行方式

### 1. 运行端到端协议模拟流程

你可以直接运行 `main.go` 观察控制台输出的完整生命周期，包括 DKG 分布式密钥生成、凭证聚合、ZKP 认证以及多重签名的最后验证。控制台还会打印出用于实验的关键密码学参数。

```bash
cd backend
go run main.go
```

### 2. 运行性能基准测试 (Benchmark)

针对大论文第六章，本项目内置了自动化基准测试套件，可用于直接测量计算耗时与空间通信开销。

```bash
cd backend/benchmark
go test -v -bench=.
```

测量的指标包含：
- 随着授权机构增加，服务提供者 (SP) 验证聚合签名的耗时。
- 客户端 (Holder) 生成 VP 证明材料的计算开销。
- 授权机构 (Verifier) 验证 ZKP 并生成部分签名的计算开销。
- 各个阶段 DID、VC、VP 数据包的 JSON 序列化大小。

### 3. 运行异常流拦截测试

测试当 RA 节点宕机导致 Holder 收集的凭证不足门限值时，系统如何通过 ZKP 数学完备性拦截伪造请求。

```bash
cd backend
go test -v -run TestSimulator_ExceptionFlow_InsufficientCredentials
```

## 版权与使用声明

本项目代码及相关实现受版权保护。
**未经原作者（牟翰翔）授权，严禁将本项目用于任何商业用途、公开发表或二次分发。**
如需在学术研究、工程项目中引用或使用本软件，请务必提前与作者取得联系并获得许可。
