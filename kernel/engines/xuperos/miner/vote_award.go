package miner

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/tx"
	lpb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	"github.com/superconsensus-chain/xupercore/protos"
	"math"
	"math/big"
	"strconv"
)


func (t *Miner) GenerateVoteAward(address string ,remainAward *big.Int) ([]*lpb.Transaction, error) {
	//Voters := make(map[string]*big.Int)
	//奖励交易
	txs := make([]*lpb.Transaction, 0)

	key := "cache_" + address
	table := &protos.CacheVoteCandidate{}
	PbTxBuf, kvErr := t.ctx.Ledger.ConfirmedTable.Get([]byte(key))
	if kvErr != nil {
		return nil , kvErr
	}
	parserErr := proto.Unmarshal(PbTxBuf, table)
	if parserErr != nil{
		fmt.Printf("D__分配奖励读CacheVoteCandidate表错误\n")
		return nil , kvErr
	}

	//遍历投票表
	totalAmount := big.NewInt(0)
	totalAmount.SetString(table.TotalVote,10)
	for key ,data := range table.VotingUser{
		r := new(big.Rat)
		newdata := big.NewInt(0)
		newdata.SetString(data,10)
		r.SetString(fmt.Sprintf("%d/%d", newdata.Int64(), totalAmount.Int64()))
		ratio, err := strconv.ParseFloat(r.FloatString(16), 10)
		if err != nil {
			fmt.Printf("D__[Vote_Award] fail to ratio parse float64", "err", err)
			return nil, err
		}
		//投票奖励
		voteAward := t.CalcVoteAward(remainAward.Int64(), ratio)
		ratioStr := fmt.Sprintf("%.16f", ratio)
		fmt.Printf("D__打印分成radtio %s \n",ratioStr)
		//奖励为0的不生成交易
		if voteAward.Int64() == 0 {
			continue
		}
		//生成交易
		voteawardtx, err := tx.GenerateVoteAwardTx([]byte(key), voteAward.String(), []byte{'1'})
		if err != nil {
			fmt.Printf("D__[Vote_Award] fail to generate vote award tx", "err", err)
			return nil, err
		}
		txs = append(txs, voteawardtx)
	}
	return txs, nil
}

func (t *Miner) AssignRewards (address string,blockAward *big.Int)(*big.Int){
	award := big.NewInt(0)
	//读缓存表
	key := "cache_" + address
	table := &protos.CacheVoteCandidate{}
	PbTxBuf, kvErr := t.ctx.Ledger.ConfirmedTable.Get([]byte(key))
	if kvErr != nil {
		return award
	}
	parserErr := proto.Unmarshal(PbTxBuf, table)
	if table.TotalVote == "0" || table.TotalVote == ""{
		return award
	}
	if parserErr != nil{
		fmt.Printf("D__分配奖励读UserReward表错误\n")
		return award
	}
	ratData := table.Ratio
	award.Mul(blockAward,big.NewInt(ratData)).Div(award,big.NewInt(100))
	return award
}

//计算投票奖励
func (t *Miner) CalcVoteAward(voteAward int64, ratio float64) *big.Int {
	award := big.NewInt(0)
	if voteAward == 0 || ratio == 0 {
		return award
	}
	//奖励*票数占比
	realAward := float64(voteAward) * ratio
	N := int64(math.Floor(realAward)) //向下取整
	award.SetInt64(N)
	return award
}
