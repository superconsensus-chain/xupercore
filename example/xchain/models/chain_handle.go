package models

import (
	"math/big"

	lpb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	sctx "github.com/superconsensus-chain/xupercore/example/xchain/common/context"
	xctx "github.com/superconsensus-chain/xupercore/kernel/common/xcontext"
	ecom "github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/common"
	"github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/reader"
	"github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/xpb"
	"github.com/superconsensus-chain/xupercore/lib/logs"
	"github.com/superconsensus-chain/xupercore/protos"
)

type ChainHandle struct {
	bcName string
	reqCtx sctx.ReqCtx
	log    logs.Logger
	chain  ecom.Chain
}

func NewChainHandle(bcName string, reqCtx sctx.ReqCtx) (*ChainHandle, error) {
	if bcName == "" || reqCtx == nil || reqCtx.GetEngine() == nil {
		return nil, ecom.ErrParameter
	}

	chain, err := reqCtx.GetEngine().Get(bcName)
	if err != nil {
		return nil, ecom.ErrChainNotExist
	}

	obj := &ChainHandle{
		bcName: bcName,
		reqCtx: reqCtx,
		log:    reqCtx.GetLog(),
		chain:  chain,
	}
	return obj, nil
}

func (t *ChainHandle) SubmitTx(tx *lpb.Transaction) error {
	return t.chain.SubmitTx(t.genXctx(), tx)
}

func (t *ChainHandle) PreExec(req []*protos.InvokeRequest,
	initiator string, authRequires []string) (*protos.InvokeResponse, error) {
	return t.chain.PreExec(t.genXctx(), req, initiator, authRequires)
}

func (t *ChainHandle) QueryTx(txId []byte) (*xpb.TxInfo, error) {
	return reader.NewLedgerReader(t.chain.Context(), t.genXctx()).QueryTx(txId)
}

func (t *ChainHandle) SelectUtxo(account string, need *big.Int,
	isLock, isExclude bool) (*lpb.UtxoOutput, error) {
	return reader.NewUtxoReader(t.chain.Context(), t.genXctx()).SelectUTXO(account, need,
		isLock, isExclude)
}

func (t *ChainHandle) QueryBlock(blkId []byte, needContent bool) (*xpb.BlockInfo, error) {
	return reader.NewLedgerReader(t.chain.Context(), t.genXctx()).QueryBlock(blkId, needContent)
}

func (t *ChainHandle) QueryChainStatus(needBranch bool) (*xpb.ChainStatus, error) {
	return reader.NewChainReader(t.chain.Context(), t.genXctx()).GetChainStatus()
}

func (t *ChainHandle) genXctx() xctx.XContext {
	return &xctx.BaseCtx{
		XLog:  t.reqCtx.GetLog(),
		Timer: t.reqCtx.GetTimer(),
	}
}
