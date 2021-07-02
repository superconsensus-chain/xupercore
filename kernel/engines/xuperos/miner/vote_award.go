package miner

import (
	lpb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	"math"
	"math/big"
)

//func NewM() map[string]map[string][]byte {
//	a := make(map[string]map[string][]byte)
//	return a
//}
//
////构建参数，合约那边需要
//func NewNominateArgs( ) map[string][]byte {
//	a := make(map[string][]byte)
//	//a["from"] = from
//	//a["amount"] = amount
//	//a["to"] = to
//	//a["lock_type"] = []byte("tdpos")
//	return a
//}

func (t *Miner) GenerateVoteAward(address string ,remainAward *big.Int) ([]*lpb.Transaction, error) {
	//Voters := make(map[string]*big.Int)
	//奖励交易
	txs := make([]*lpb.Transaction, 0)

	//KernMethod := new(governToken.KernMethod)
	//fakeCtx := mock.NewFakeKContext(NewNominateArgs(), NewM())
	//voters,TotalVote,Ratio:= KernMethod.GetVoters(fakeCtx,address)
	//if voters == nil || TotalVote == nil || Ratio==0 {
	//	return nil, nil
	//}
	////遍历投票表
	//for key ,data := range voters {
	//	//投票占比
	//	r := new(big.Rat)
	//	r.SetString(fmt.Sprintf("%d/%d", data, TotalVote))
	//	ratio, err := strconv.ParseFloat(r.FloatString(16), 10)
	//	if err != nil {
	//		fmt.Printf("D__分红比例转换失败\n")
	//		return nil, err
	//	}
	//	//投票奖励
	//	voteAward := t.CalcVoteAward(remainAward.Int64(), ratio)
	//	ratioStr := fmt.Sprintf("%.16f", ratio)
	//	fmt.Printf("D__打印分成radtio %s \n",ratioStr)
	//	//奖励为0的不生成交易
	//	if voteAward.Int64() == 0 {
	//		continue
	//	}
	//	//生成交易
	//	voteawardtx, err := tx.GenerateVoteAwardTx([]byte(key),voteAward.String(),[]byte{'1'})
	//	if err != nil {
	//		fmt.Printf("D__分红[Vote_Award] fail to generate vote award tx", "err", err)
	//		return nil, err
	//	}
	//	txs = append(txs, voteawardtx)
	//	fmt.Printf("D__当前交易id : %s \n",hex.EncodeToString(voteawardtx.Txid))
	//}

	return txs, nil
}

func (t *Miner) AssignRewards (address string,blockAward *big.Int)(*big.Int){
	award := big.NewInt(0)
	//KernMethod := new(governToken.KernMethod)
	//fakeCtx := mock.NewFakeKContext(NewNominateArgs(), NewM())
	//ratData  := KernMethod.GetRewardRatio(fakeCtx,address)
	//if ratData == 0 {
	//	return award
	//}
	//award.Mul(blockAward,big.NewInt(ratData)).Div(award,big.NewInt(100))

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

//刷新缓存数据
func (t *Miner) updateCacheTable() error {
	//KernMethod := new(governToken.KernMethod)
	//fakeCtx := mock.NewFakeKContext(NewNominateArgs(), NewM())
	//err := KernMethod.UpdateCacheTable(fakeCtx)
	//if err != nil {
	//	fmt.Printf("D__异常错误，新的周期刷缓存表错误\n")
	//	return nil
	//}
	////缓存表加载分红比例
	//keytalbe := "cached_dividend_table"
	//user , err  := KernMethod.GetRatio(fakeCtx)
	////将user写入表
	//batch := t.ctx.State.NewBatch()
	//table := &protos.ProposalRatio{}
	//table.UserRatio = user
	//pbTxBuf, err := proto.Marshal(table)
	//if err != nil {
	//	fmt.Printf("D__解析ProposalRatio失败\n")
	//	return err
	//}
	//batch.Put(append([]byte(lpb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)
	////原子写入
	//writeErr := batch.Write()
	//if writeErr != nil {
	//	fmt.Printf("D__刷新缓存时原子写入错误error %s , \n", writeErr)
	//	return writeErr
	//}
	return nil
}