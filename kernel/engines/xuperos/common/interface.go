package common

import (
	"github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/ledger"
	"github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/state"
	lpb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	xconf "github.com/superconsensus-chain/xupercore/kernel/common/xconfig"
	xctx "github.com/superconsensus-chain/xupercore/kernel/common/xcontext"
	"github.com/superconsensus-chain/xupercore/kernel/consensus"
	"github.com/superconsensus-chain/xupercore/kernel/contract"
	governToken "github.com/superconsensus-chain/xupercore/kernel/contract/proposal/govern_token"
	"github.com/superconsensus-chain/xupercore/kernel/contract/proposal/propose"
	timerTask "github.com/superconsensus-chain/xupercore/kernel/contract/proposal/timer"
	"github.com/superconsensus-chain/xupercore/kernel/engines"
	kledger "github.com/superconsensus-chain/xupercore/kernel/ledger"
	"github.com/superconsensus-chain/xupercore/kernel/network"
	aclBase "github.com/superconsensus-chain/xupercore/kernel/permission/acl/base"
	cryptoBase "github.com/superconsensus-chain/xupercore/lib/crypto/client/base"
	"github.com/superconsensus-chain/xupercore/protos"
)

type Chain interface {
	// 获取链上下文
	Context() *ChainCtx
	// 启动链
	Start()
	// 关闭链
	Stop()
	// 合约预执行
	PreExec(xctx.XContext, []*protos.InvokeRequest, string, []string) (*protos.InvokeResponse, error)
	// 提交交易
	SubmitTx(xctx.XContext, *lpb.Transaction) error
	// 处理新区块
	ProcBlock(xctx.XContext, *lpb.InternalBlock) error
	// 设置依赖实例化代理
	SetRelyAgent(ChainRelyAgent) error
}

// 定义xuperos引擎对外暴露接口
// 依赖接口而不是依赖具体实现
type Engine interface {
	engines.BCEngine
	Context() *EngineCtx
	Get(string) (Chain, error)
	GetChains() []string
	SetRelyAgent(EngineRelyAgent) error
}

// 定义引擎对各组件依赖接口约束
type EngineRelyAgent interface {
	CreateNetwork(*xconf.EnvConf) (network.Network, error)
}

// 定义链对各组件依赖接口约束
type ChainRelyAgent interface {
	CreateLedger() (*ledger.Ledger, error)
	CreateState(*ledger.Ledger, cryptoBase.CryptoClient) (*state.State, error)
	CreateContract(kledger.XMReader) (contract.Manager, error)
	CreateConsensus() (consensus.ConsensusInterface, error)
	CreateCrypto(cryptoType string) (cryptoBase.CryptoClient, error)
	CreateAcl() (aclBase.AclManager, error)
	CreateGovernToken() (governToken.GovManager, error)
	CreateProposal() (propose.ProposeManager, error)
	CreateTimerTask() (timerTask.TimerManager, error)
	CreateParaChain() error
}
