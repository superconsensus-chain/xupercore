package reader

import (
	"github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/ledger"
	lpb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	xctx "github.com/superconsensus-chain/xupercore/kernel/common/xcontext"
	"github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/common"
	"github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/xpb"
	"github.com/superconsensus-chain/xupercore/lib/logs"
	"github.com/superconsensus-chain/xupercore/lib/utils"
	"github.com/superconsensus-chain/xupercore/protos"
	"github.com/golang/protobuf/proto"
	"strconv"
	"encoding/json"
	"math/big"
	"fmt"
)

type ValidatorsInfo struct {
	Validators   []string `json:"validators"`
	Miner        string   `json:"miner"`
	Curterm      int64    `json:"curterm"`
	ContractInfo string   `json:"contract"`
}

type LedgerReader interface {
	// 查询交易信息（QueryTx）
	QueryTx(txId []byte) (*xpb.TxInfo, error)
	// 查询区块ID信息（GetBlock）
	QueryBlock(blkId []byte, needContent bool) (*xpb.BlockInfo, error)
	// 通过区块高度查询区块信息（GetBlockByHeight）
	QueryBlockByHeight(height int64, needContent bool) (*xpb.BlockInfo, error)
	//测试
	Test(address string)(*protos.CandidateRatio,error)
	//
	PledgeVotingRecords(address string)(*protos.PledgeVotingResponse,error)
	//
	GetVerification(address string)(*protos.VerificationTable,error)

	GetSystemStatusExplorer()(*protos.BCStatusExplorer,error)
}

type ledgerReader struct {
	chainCtx *common.ChainCtx
	baseCtx  xctx.XContext
	log      logs.Logger
}

func NewLedgerReader(chainCtx *common.ChainCtx, baseCtx xctx.XContext) LedgerReader {
	if chainCtx == nil || baseCtx == nil {
		return nil
	}

	reader := &ledgerReader{
		chainCtx: chainCtx,
		baseCtx:  baseCtx,
		log:      baseCtx.GetLog(),
	}

	return reader
}

func (t *ledgerReader) QueryTx(txId []byte) (*xpb.TxInfo, error) {
	out := &xpb.TxInfo{}
	tx, err := t.chainCtx.Ledger.QueryTransaction(txId)
	if err != nil {
		t.log.Warn("ledger query tx error", "txId", utils.F(txId), "error", err)
		out.Status = lpb.TransactionStatus_TX_NOEXIST
		if err == ledger.ErrTxNotFound {
			// 查询unconfirmed表
			tx, _, err = t.chainCtx.State.QueryTx(txId)
			if err != nil {
				t.log.Warn("state query tx error", "txId", utils.F(txId), "error", err)
				return nil, common.ErrTxNotExist
			}
			t.log.Debug("state query tx succeeded", "txId", utils.F(txId))
			out.Status = lpb.TransactionStatus_TX_UNCONFIRM
			out.Tx = tx
			return out, nil
		}

		return nil, common.ErrTxNotExist
	}

	// 查询block状态，是否被分叉
	block, err := t.chainCtx.Ledger.QueryBlockHeader(tx.Blockid)
	if err != nil {
		t.log.Warn("query block error", "txId", utils.F(txId), "blockId", utils.F(tx.Blockid), "error", err)
		return nil, common.ErrBlockNotExist
	}

	t.log.Debug("query block succeeded", "txId", utils.F(txId), "blockId", utils.F(tx.Blockid))
	meta := t.chainCtx.Ledger.GetMeta()
	out.Tx = tx
	if block.InTrunk {
		out.Distance = meta.TrunkHeight - block.Height
		out.Status = lpb.TransactionStatus_TX_CONFIRM
	} else {
		out.Status = lpb.TransactionStatus_TX_FURCATION
	}

	return out, nil
}

// 注意不需要交易内容的时候不要查询
func (t *ledgerReader) QueryBlock(blkId []byte, needContent bool) (*xpb.BlockInfo, error) {
	out := &xpb.BlockInfo{}
	block, err := t.chainCtx.Ledger.QueryBlock(blkId)
	if err != nil {
		if err == ledger.ErrBlockNotExist {
			out.Status = lpb.BlockStatus_BLOCK_NOEXIST
			return out, common.ErrBlockNotExist
		}

		t.log.Warn("query block error", "err", err)
		return nil, common.ErrBlockNotExist
	}

	if needContent {
		out.Block = block
	}

	if block.InTrunk {
		out.Status = lpb.BlockStatus_BLOCK_TRUNK
	} else {
		out.Status = lpb.BlockStatus_BLOCK_BRANCH
	}

	return out, nil
}

// 注意不需要交易内容的时候不要查询
func (t *ledgerReader) QueryBlockByHeight(height int64, needContent bool) (*xpb.BlockInfo, error) {
	out := &xpb.BlockInfo{}
	block, err := t.chainCtx.Ledger.QueryBlockByHeight(height)
	if err != nil {
		if err == ledger.ErrBlockNotExist {
			out.Status = lpb.BlockStatus_BLOCK_NOEXIST
			return out, nil
		}

		t.log.Warn("query block by height error", "err", err)
		return nil, common.ErrBlockNotExist
	}

	if needContent {
		out.Block = block
	}

	if block.InTrunk {
		out.Status = lpb.BlockStatus_BLOCK_TRUNK
	} else {
		out.Status = lpb.BlockStatus_BLOCK_BRANCH
	}

	return out, nil
}

func (t *ledgerReader)Test(address string)(*protos.CandidateRatio,error){

	out := &protos.CandidateRatio{}
	keytable := "ballot_" + address
	PbTxBuf, kvErr := t.chainCtx.Ledger.ConfirmedTable.Get([]byte(keytable))
	if(kvErr != nil) {
		return nil, kvErr
	}
	parserErr := proto.Unmarshal(PbTxBuf, out)
	if parserErr != nil  {
		return nil,parserErr
	}

	return out,nil
}
func (t *ledgerReader)PledgeVotingRecords(address string)(*protos.PledgeVotingResponse,error){


	out := &protos.PledgeVotingResponse{}

	CandidateRatio := &protos.CandidateRatio{}
	VoteDetails := []*protos.VoteDetailsStatus{}
	_,error := t.ReadUserBallot(address,CandidateRatio)
	if error != nil {
		return nil,error
	}
	out.TotalAmount = CandidateRatio.TatalVote
	out.UsedAmount = CandidateRatio.Used
	//获取冻结信息表
	FrozenAssetsTable := &protos.FrozenAssetsTable{}
	keytable :=  "amount_" + address
	PbTxBuf, kvErr := t.chainCtx.Ledger.ConfirmedTable.Get([]byte(keytable))
	if(kvErr != nil) {
		return nil,kvErr
	}
	parserErr := proto.Unmarshal(PbTxBuf, FrozenAssetsTable)
	if parserErr != nil  {
		return nil,kvErr
	}
	out.FrozenAssetsTable = FrozenAssetsTable

	//获取冻结中的，也就是申请解冻
	var thawAmount int64
	for _ ,data := range FrozenAssetsTable.ThawDetail{
		value, err := strconv.ParseInt(data.Amount, 10, 64)
		if err == nil {
			thawAmount += value
		}
	}
	freeString := strconv.FormatInt(thawAmount,10)
	out.FreezeAmount = freeString

	//获取投票信息
	for key ,data := range CandidateRatio.MyVoting{
		VoteDetailsStatus := &protos.VoteDetailsStatus{}
		//获取奖励比
		userBallot := &protos.CandidateRatio{}
		_,err := t.ReadUserBallot(key,userBallot)
		if err != nil {
			return out,nil
		}
		VoteDetailsStatus.Ratio = int32(userBallot.Ratio)
		VoteDetailsStatus.Toaddr = key
		VoteDetailsStatus.Ballots, _ = strconv.ParseInt(data,10,64)
		VoteDetailsStatus.Totalballots = userBallot.BeVotedTotal
		//投票为0就不显示了
		if VoteDetailsStatus.Ballots != 0 {
			VoteDetails = append(VoteDetails,VoteDetailsStatus )
		}

	}
	out.VoteDetailsStatus = VoteDetails
	out.MyVote = int64(len(VoteDetails))

	return out, nil
}

func (t *ledgerReader) ReadUserBallot(operator string,table *protos.CandidateRatio) (*protos.CandidateRatio,error) {
	keytable := "ballot_" + operator
	PbTxBuf, kvErr := t.chainCtx.Ledger.ConfirmedTable.Get([]byte(keytable))
	if(kvErr != nil) {
		return nil,kvErr
	}
	parserErr := proto.Unmarshal(PbTxBuf, table)
	if parserErr != nil  {
		return nil,kvErr
	}
	return table,nil
}

func (t *ledgerReader)GetSystemStatusExplorer()(*protos.BCStatusExplorer,error){
	out := &protos.BCStatusExplorer{}
	//获取全网总知产
	out.TotalMoney=t.chainCtx.State.GetMeta().UtxoTotal
	//获取当前高度
	out.Height = t.chainCtx.Ledger.GetMeta().TrunkHeight

	//从所有候选人里面读
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr := t.chainCtx.Ledger.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			t.log.Warn("D__解析tdpos_freezes_total_assets失败", "err", parserErr)
			return out,nil
		}
	}else {
		t.log.Warn("D__解析tdpos_freezes_total_assets为空")
		return out,nil
	}

	//获取冻结总资产
	out.FreeMonry = freetable.Freemonry
	//计算冻结百分比
	//fmt.Printf("D__打印FreeMonry %s \n",out.FreeMonry)
	if out.FreeMonry == ""{
		return out,nil
	}
	free , _ := new(big.Int).SetString(out.FreeMonry, 10)
	total , _ := new(big.Int).SetString(out.TotalMoney,10)
	free.Mul(free,big.NewInt(10000))
	ratio := free.Div(free,total).Int64()
	out.Percentage = fmt.Sprintf("%.2f", float64(ratio)/100)
	out.Percentage += "%"

	return out,nil
}

func (t *ledgerReader)GetVerification(address string)(*protos.VerificationTable,error){
	//fmt.Printf("D__进入GetVerification\n")
	out := &protos.VerificationTable{}

	//获取当前出块的人
	LedgerMeta := t.chainCtx.Ledger.GetMeta()
	tipBlockId := LedgerMeta.TipBlockid
	Block, err := t.chainCtx.Ledger.QueryBlock(tipBlockId)
	if err != nil {
		t.log.Warn("query block error", "err", err, "blockId", tipBlockId)
		return nil, common.ErrBlockNotExist
	}
	curBlockNum := Block.CurBlockNum
	proposer := string(Block.Proposer)
	cycle := 0

	//获取tdpos出块验证人
	cons , error := t.chainCtx.Consensus.GetConsensusStatus()
	if error != nil{
		return nil, error
	}
	validators_info := cons.GetCurrentValidatorsInfo()
	ValidatorsInfo := &ValidatorsInfo{}
	jsErr := json.Unmarshal(validators_info,ValidatorsInfo)
	if jsErr != nil {
		return nil, jsErr
	}
	//fmt.Printf("D__打印ValidatorsInfo： %s \n",ValidatorsInfo)
	//先读取当前一轮验证人的信息
	for _ , data := range ValidatorsInfo.Validators {
		//fmt.Printf("D__打印当前验证人: %s \n",data)
		CandidateRatio := &protos.CandidateRatio{}
		VerificationInfo := &protos.VerificationInfo{}
		_,error := t.ReadUserBallot(data,CandidateRatio)
		if error == nil && CandidateRatio.Ratio != 0{
			//fmt.Printf("D__打印当前CandidateRatio: %s\n",CandidateRatio)
			VerificationInfo.Total = CandidateRatio.BeVotedTotal
			if VerificationInfo.Total == ""{
				VerificationInfo.Total = "0"
			}
			VerificationInfo.Ratio = int32(CandidateRatio.Ratio)
			value , ok := CandidateRatio.VotingUser[address]
			if ok {
				free , _ := new(big.Int).SetString(value, 10)
				total , _ := new(big.Int).SetString(CandidateRatio.BeVotedTotal,10)
				free.Mul(free,big.NewInt(10000))
				if total.Int64() > 0 {
					ratio := free.Div(free, total).Int64()
					VerificationInfo.Percentage = fmt.Sprintf("%.2f", float64(ratio)/100)
					VerificationInfo.Percentage += "%"
					VerificationInfo.MyTotal = value
				} else {
					VerificationInfo.Percentage = "0%"
					VerificationInfo.MyTotal = "0"
				}
			}else {
				VerificationInfo.Percentage = "0%"
				VerificationInfo.MyTotal = "0"
			}
			if out.Verification == nil {
				out.Verification = make(map[string]*protos.VerificationInfo)
			}
			out.Verification[data] = VerificationInfo
		}
	}
	out.Len = int64(len(out.Verification))

	for _ , data := range ValidatorsInfo.Validators {
		if proposer != data { //判断出块到哪个验证人了
			cycle++
		}else {
			break
		}
	}

	//从所有候选人里面读
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr := t.chainCtx.Ledger.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			t.log.Warn("D__解析tdpos_freezes_total_assets失败", "err", parserErr)
			return out,nil
		}
	}else {
		t.log.Warn("D__解析tdpos_freezes_total_assets为空")
		return out,nil
	}
	//候选人
	for _ ,data := range freetable.Candidate{
		CandidateRatio := &protos.CandidateRatio{}
		VerificationInfo := &protos.VerificationInfo{}
		_,error := t.ReadUserBallot(data,CandidateRatio)
		if error == nil {
			VerificationInfo.Total = CandidateRatio.BeVotedTotal
			if VerificationInfo.Total == "" {
				VerificationInfo.Total = "0"
			}
			VerificationInfo.Ratio = int32(CandidateRatio.Ratio)
			value , ok := CandidateRatio.VotingUser[address]
			if ok {
				free , _ := new(big.Int).SetString(value, 10)
				total , _ := new(big.Int).SetString(CandidateRatio.BeVotedTotal,10)
				free.Mul(free,big.NewInt(10000))
				if total.Int64() > 0 {
					ratio := free.Div(free, total).Int64()
					VerificationInfo.Percentage = fmt.Sprintf("%.2f", float64(ratio)/100)
					VerificationInfo.Percentage += "%"
					VerificationInfo.MyTotal = value
				}else {
					VerificationInfo.Percentage = "0%"
					VerificationInfo.MyTotal = "0"
				}
			}else {
				VerificationInfo.Percentage = "0%"
				VerificationInfo.MyTotal = "0"
			}
			if out.Candidate == nil {
				out.Candidate = make(map[string]*protos.VerificationInfo)
			}
			//_ , ok = out.Verification[data]
			//if  !ok {
			out.Candidate[data] = VerificationInfo
			//}
		}
	}
	out.LenCandidate = int64(len(out.Candidate))
	//fmt.Printf("D__验证人获取完毕\n")

	index := out.Len - int64(cycle)
	out.TimeLeft = index*60 - curBlockNum*3
	if out.TimeLeft < 0 {
		out.TimeLeft = 0
	}
	return out, nil
}