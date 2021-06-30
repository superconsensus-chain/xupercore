package govern_token

import (
	"encoding/json"
	"fmt"
	"math/big"

	xledger "github.com/xuperchain/xupercore/bcs/ledger/xledger/ledger"
	"github.com/xuperchain/xupercore/kernel/contract"
	"github.com/xuperchain/xupercore/kernel/contract/proposal/utils"
)

type KernMethod struct {
	BcName               string
	NewGovResourceAmount int64
	Predistribution      []xledger.Predistribution
}

func NewKernContractMethod(bcName string, NewGovResourceAmount int64, Predistribution []xledger.Predistribution) *KernMethod {
	t := &KernMethod{
		BcName:               bcName,
		NewGovResourceAmount: NewGovResourceAmount,
		Predistribution:      Predistribution,
	}
	return t
}

func (t *KernMethod) InitGovernTokens(ctx contract.KContext) (*contract.Response, error) {
	// 判断是否已经初始化
	res, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(utils.GetDistributedKey()))
	if err == nil && string(res) == "true" {
		return &contract.Response{
			Status:  utils.StatusOK,
			Message: "success",
			Body:    []byte("Govern tokens has been initialized"),
		}, fmt.Errorf("Govern tokens has been initialized.")
	}

	totalSupply := big.NewInt(0)
	for _, ps := range t.Predistribution {
		amount := big.NewInt(0)
		amount.SetString(ps.Quota, 10)
		if amount.Cmp(big.NewInt(0)) < 0 {
			return nil, fmt.Errorf("init gov tokens failed, parse genesis account error, negative amount")
		}

		balance := utils.NewGovernTokenBalance()
		balance.TotalBalance = amount

		balanceBuf, err := json.Marshal(balance)
		if err != nil {
			return nil, err
		}

		// 设置初始账户的govern token余额
		key := utils.MakeAccountBalanceKey(ps.Address)
		err = ctx.Put(utils.GetGovernTokenBucket(), []byte(key), balanceBuf)
		if err != nil {
			return nil, err
		}

		// 更新余额
		totalSupply = totalSupply.Add(totalSupply, amount)
	}

	// 保存总额
	key := utils.MakeTotalSupplyKey()
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(key), []byte(totalSupply.String()))
	if err != nil {
		return nil, err
	}

	// 设置已经初始化的标志
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(utils.GetDistributedKey()), []byte("true"))
	if err != nil {
		return nil, err
	}

	delta := contract.Limits{
		XFee: t.NewGovResourceAmount,
	}
	ctx.AddResourceUsed(delta)

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    nil,
	}, nil
}

func (t *KernMethod)CheckTokens(ctx contract.KContext,amount *big.Int) (error) {
	args := ctx.Args()
	sender:= args["to"]
	lockTypeBuf := args["lock_type"]
	//获取当前剩余
	if sender == nil  {
		return fmt.Errorf("D__sender is nil ")
	}
	// 校验场景
	lockType := string(lockTypeBuf)
	if lockType != utils.GovernTokenTypeOrdinary && lockType != utils.GovernTokenTypeTDPOS {
		return fmt.Errorf("lock gov tokens failed, lock_type invalid: %s", lockType)
	}
	// 查询sender余额
	senderBalance, err := t.balanceOf(ctx, string(sender))
	if err != nil {
		return fmt.Errorf("transfer gov tokens failed, query sender balance error")
	}
	availableBalance := big.NewInt(0)
	availableBalance.Sub(senderBalance.TotalBalance, senderBalance.LockedBalance[lockType])
	if availableBalance.Cmp(amount) == -1 {
		return fmt.Errorf("lock gov tokens failed, account available balance insufficient")
	}

	return nil
}

func (t *KernMethod) TransferGovernTokens(ctx contract.KContext) (*contract.Response, error) {
	//if ctx.ResourceLimit().XFee < t.NewGovResourceAmount/1000 {
	//	return nil, fmt.Errorf("gas not enough, expect no less than %d", t.NewGovResourceAmount/1000)
	//}
	args := ctx.Args()
	//sender := ctx.Initiator()
	sender := args["from"]
	receiverBuf := args["to"]
	amountBuf := args["amount"]
	if sender == nil || receiverBuf == nil || amountBuf == nil {
		return nil, fmt.Errorf("transfer gov tokens failed, sender,to is nil or amount is nil")
	}

	amount := big.NewInt(0)
	_, isAmount := amount.SetString(string(amountBuf), 10)
	if !isAmount || amount.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("transfer gov tokens failed, parse amount error")
	}

	// 查询sender余额
	senderBalance, err := t.balanceOf(ctx, string(sender))
	if err != nil {
		return nil, fmt.Errorf("transfer gov tokens failed, query sender balance error")
	}

	// 比较并更新sender余额
	for _, v := range senderBalance.LockedBalance {
		tmpAmount := big.NewInt(0)
		tmpAmount.Sub(senderBalance.TotalBalance, v)
		if tmpAmount.Cmp(amount) < 0 {
			return nil, fmt.Errorf("transfer gov tokens failed, sender's insufficient balance")
		}
	}
	senderBalance.TotalBalance.Sub(senderBalance.TotalBalance, amount)

	// 设置receiver余额
	receiverBalance := utils.NewGovernTokenBalance()
	receiverBalance.TotalBalance.Set(amount)

	// 查询receiver余额并更新
	receiverKey := utils.MakeAccountBalanceKey(string(receiverBuf))
	receiverBalanceBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(receiverKey))
	if err == nil {
		receiverBalanceOld := &utils.GovernTokenBalance{}
		json.Unmarshal(receiverBalanceBuf, receiverBalanceOld)
		receiverBalance.TotalBalance.Add(receiverBalance.TotalBalance, receiverBalanceOld.TotalBalance)
	}

	// 更新sender余额
	senderBalanceBuf, _ := json.Marshal(senderBalance)
	senderKey := utils.MakeAccountBalanceKey(string(sender))
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(senderKey), senderBalanceBuf)
	if err != nil {
		return nil, fmt.Errorf("transfer gov tokens failed, update sender's balance")
	}

	// 更新receiver余额
	receiverBalanceBuf, _ = json.Marshal(receiverBalance)
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(receiverKey), receiverBalanceBuf)
	if err != nil {
		return nil, fmt.Errorf("transfer gov tokens failed, update receriver's balance")
	}

	delta := contract.Limits{
		XFee: t.NewGovResourceAmount / 1000,
	}
	ctx.AddResourceUsed(delta)

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    nil,
	}, nil
}

func (t *KernMethod) LockGovernTokens(ctx contract.KContext) (*contract.Response, error) {
	// 调用权限校验
	if ctx.Caller() != utils.ProposalKernelContract && ctx.Caller() != utils.TDPOSKernelContract && ctx.Caller() != utils.XPOSKernelContract {
		return nil, fmt.Errorf("caller %s no authority to LockGovernTokens", ctx.Caller())
	}
	args := ctx.Args()
	accountBuf := args["from"]
	amountBuf := args["amount"]
	lockTypeBuf := args["lock_type"]
	to := args["to"]
	if accountBuf == nil || amountBuf == nil || lockTypeBuf == nil || to == nil {
		return nil, fmt.Errorf("lock gov tokens failed, account, amount , lock_type or to is nil")
	}

	// 校验场景
	lockType := string(lockTypeBuf)
	if lockType != utils.GovernTokenTypeOrdinary && lockType != utils.GovernTokenTypeTDPOS {
		return nil, fmt.Errorf("lock gov tokens failed, lock_type invalid: %s", lockType)
	}

	// 查询account余额
	accountBalance, err := t.balanceOf(ctx, string(accountBuf))
	if err != nil {
		return nil, fmt.Errorf("lock gov tokens failed, query account balance error")
	}
	amountLock := big.NewInt(0)
	amountLock.SetString(string(amountBuf), 10)
	// 比较account available balance amount
	availableBalance := big.NewInt(0)
	availableBalance.Sub(accountBalance.TotalBalance, accountBalance.LockedBalance[lockType])
	if availableBalance.Cmp(amountLock) == -1 {
		return nil, fmt.Errorf("lock gov tokens failed, account available balance insufficient")
	}

	accountBalance.LockedBalance[lockType].Add(accountBalance.LockedBalance[lockType], amountLock)

	// 更新account余额
	accountBalanceBuf, _ := json.Marshal(accountBalance)
	accountKey := utils.MakeAccountBalanceKey(string(accountBuf))

	//参数类型判断
	ratio := args["ratio"]
	//ratio不为空，提名候选人，为空表示普通投票
	if ratio == nil {
		amountRatio := big.NewInt(0)
		amountRatio.SetString(string(ratio), 10)
		if amountRatio.Int64() > 100 || amountRatio.Int64() < 0 {
			return nil, fmt.Errorf("D__ratio参数范围取错。必须在0-100之间 ")
		}
		error := t.writeCandidateTable(ctx,string(to),amountRatio.Int64(),true)
		if error != nil {
			return nil, err
		}
	}else {
		amountVote:= big.NewInt(0)
		amountVote.SetString(string(amountBuf), 10)
		if amountVote.Int64() < 0 {
			return nil, fmt.Errorf("D__Vote 必须大于0 ")
		}
		error := t.writeVoteTable(ctx,string(accountBuf),string(to),amountVote,true)
		if error != nil {
			return nil, err
		}
	}

	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(accountKey), accountBalanceBuf)
	if err != nil {
		return nil, fmt.Errorf("transfer gov tokens failed, update sender's balance")
	}

	delta := contract.Limits{
		XFee: t.NewGovResourceAmount / 1000,
	}
	ctx.AddResourceUsed(delta)

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    nil,
	}, nil
}

func (t *KernMethod) UnLockGovernTokens(ctx contract.KContext) (*contract.Response, error) {
	// 调用权限校验
	if ctx.Caller() != utils.ProposalKernelContract && ctx.Caller() != utils.TDPOSKernelContract && ctx.Caller() != utils.XPOSKernelContract {
		return nil, fmt.Errorf("caller %s no authority to UnLockGovernTokens", ctx.Caller())
	}
	args := ctx.Args()
	accountBuf := args["from"]
	amountBuf := args["amount"]
	lockTypeBuf := args["lock_type"]
	to := args["to"]
	if accountBuf == nil || amountBuf == nil || lockTypeBuf == nil {
		return nil, fmt.Errorf("lock gov tokens failed, account, amount or lock_type is nil")
	}

	// 查询account余额
	accountBalance, err := t.balanceOf(ctx, string(accountBuf))
	if err != nil {
		return nil, fmt.Errorf("unlock gov tokens failed, query account balance error")
	}
	amountLock := big.NewInt(0)
	amountLock.SetString(string(amountBuf), 10)
	// 解锁account balance amount
	lockType := string(lockTypeBuf)
	if lockType != utils.GovernTokenTypeOrdinary && lockType != utils.GovernTokenTypeTDPOS {
		return nil, fmt.Errorf("unlock gov tokens failed, lock_type invalid: %s", lockType)
	}
	accountBalance.LockedBalance[lockType] = accountBalance.LockedBalance[lockType].Sub(accountBalance.LockedBalance[lockType], amountLock)

	// 更新account余额
	accountBalanceBuf, _ := json.Marshal(accountBalance)
	accountKey := utils.MakeAccountBalanceKey(string(accountBuf))

	//参数类型判断
	ratio := args["ratio"]
	//ratio不为空，提名候选人，为空表示普通投票
	if ratio == nil {
		amountRatio := big.NewInt(0)
		amountRatio.SetString(string(ratio), 10)
		if amountRatio.Int64() > 100 || amountRatio.Int64() < 0 {
			return nil, fmt.Errorf("D__ratio参数范围取错。必须在0-100之间 ")
		}
		error := t.writeCandidateTable(ctx,string(to),amountRatio.Int64(),false)
		if error != nil {
			return nil, err
		}
	}else {
		amountVote:= big.NewInt(0)
		amountVote.SetString(string(amountBuf), 10)
		if amountVote.Int64() < 0 {
			return nil, fmt.Errorf("D__Vote 必须大于0 ")
		}
		error := t.writeVoteTable(ctx,string(accountBuf),string(to),amountVote,false)
		if error != nil {
			return nil, err
		}
	}

	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(accountKey), accountBalanceBuf)
	if err != nil {
		return nil, fmt.Errorf("transfer gov tokens failed, update sender's balance")
	}

	delta := contract.Limits{
		XFee: t.NewGovResourceAmount / 1000,
	}
	ctx.AddResourceUsed(delta)

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    nil,
	}, nil
}

func (t *KernMethod) QueryAccountGovernTokens(ctx contract.KContext) (*contract.Response, error) {
	args := ctx.Args()
	accountBuf := args["account"]

	// 查询account余额
	balance, err := t.balanceOf(ctx, string(accountBuf))
	if err != nil {
		return nil, fmt.Errorf("query account gov tokens balance failed, query account balance error:%s", err.Error())
	}

	balanceResBuf, err := json.Marshal(balance)
	if err != nil {
		return nil, fmt.Errorf("query account gov tokens balance failed, error:%s", err.Error())
	}

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    balanceResBuf,
	}, nil
}

func (t *KernMethod) TotalSupply(ctx contract.KContext) (*contract.Response, error) {
	key := utils.MakeTotalSupplyKey()
	totalSupplyBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(key))
	if err != nil {
		return nil, err
	}

	totalSupply := big.NewInt(0)
	totalSupply.SetString(string(totalSupplyBuf), 10)

	return &contract.Response{
		Status:  utils.StatusOK,
		Message: "success",
		Body:    []byte(totalSupply.String()),
	}, nil

}

func (t *KernMethod) balanceOf(ctx contract.KContext, account string) (*utils.GovernTokenBalance, error) {
	accountKey := utils.MakeAccountBalanceKey(account)
	accountBalanceBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(accountKey))
	if err != nil {
		return utils.NewGovernTokenBalance(), fmt.Errorf("no sender found")
	}
	balance := utils.NewGovernTokenBalance()
	err = json.Unmarshal(accountBalanceBuf, balance)
	if err != nil {
		return utils.NewGovernTokenBalance(), fmt.Errorf("no sender found")
	}

	return balance, nil
}

func (t *KernMethod) UpdateCacheTable(ctx contract.KContext)(error){
	//accountKey := utils.MakeCacheKey(account)
	////不用获取缓冲表之前的信息，直接刷新覆盖就行了
	//
	//receiveAccountBuf , error := ctx.Get(utils.GetCacheKey(), []byte(accountKey))
	//if error == nil {
	//
	//}

	//获取全部候选人
	AllCandidata := "allCandidate"
	AllCandidataBuf , err := ctx.Get(utils.GetGovernTokenBucket(),[]byte(AllCandidata))
	AllCandidateTable := &utils.AllCandidate{}
	if AllCandidataBuf == nil  {
		fmt.Printf("D__当前还没有候选人 \n")
		return nil
	}
	err = json.Unmarshal(AllCandidataBuf,AllCandidateTable)
	if err != nil {
		return fmt.Errorf("no sender found")
	}
	for _ , data := range AllCandidateTable.Candidate{
		toKey := utils.MakevoteCandidateKey(data)
		toKeyBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(toKey))
		if toKeyBuf == nil  {
			//to提名的时候就会记录
			return fmt.Errorf("D__trem获取候选人异常错误，此候选人不存在 \n")
		}
		CandidateVote := utils.NewCandidateRatio()
		err = json.Unmarshal(toKeyBuf,CandidateVote)
		if err != nil {
			return fmt.Errorf("no sender found")
		}

		accountKey := utils.MakeCacheKey(data)
		CacheVoteCandidate := &utils.CacheVoteCandidate{}
		receiveAccountBuf , _ := ctx.Get(utils.GetCacheKey(), []byte(accountKey))
		if receiveAccountBuf == nil {
			fmt.Printf("D__第一次从缓存读取")
		}else {
			err = json.Unmarshal(receiveAccountBuf,CacheVoteCandidate)
			if err != nil {
				return fmt.Errorf("no sender found")
			}
		}
		CacheVoteCandidate.Ratio = CandidateVote.Ratio
		CacheVoteCandidate.TotalVote = CandidateVote.TotalVote
		if CacheVoteCandidate.VotingUser == nil {
			CacheVoteCandidate.VotingUser = make(map[string]*big.Int)
		}
		CacheVoteCandidate.VotingUser = CandidateVote.VotingUser

		//写表
		andidateBuf , _ := json.Marshal(CacheVoteCandidate)
		err = ctx.Put(utils.GetGovernTokenBucket(), []byte(accountKey), andidateBuf)
		if err != nil {
			return fmt.Errorf("D__更新缓存提名表错误,update sender's balance")
		}
	}

	return nil
}

//获取分红比例
func (t *KernMethod) GetRatio(ctx contract.KContext) (map[string]int64,error) {
	User := make(map[string]int64)
	AllCandidata := "allCandidate"
	AllCandidataBuf , err := ctx.Get(utils.GetGovernTokenBucket(),[]byte(AllCandidata))
	AllCandidateTable := &utils.AllCandidate{}
	if AllCandidataBuf == nil {
		return nil, nil
	}
	err = json.Unmarshal(AllCandidataBuf,AllCandidateTable)
	if err != nil {
		return nil,fmt.Errorf("D__刷钱分红比异常，no sender found")
	}
	for _ ,data := range AllCandidateTable.Candidate{
		CandidateKey := utils.MakeCacheKey(data)
		CandidateKeyBuf, err := ctx.Get(utils.GetCacheKey(),[]byte(CandidateKey))
		CacheVoteCandidate := &utils.CacheVoteCandidate{}
		if CandidateKeyBuf == nil {
			fmt.Printf("D__获取分红比未找到该候选人 \n")
			return nil, nil
		}
		err = json.Unmarshal(CandidateKeyBuf,CacheVoteCandidate)
		if err != nil {
			fmt.Printf("D__分红比获取投票异常错误 \n")
			return nil,err
		}
		User[data] = CacheVoteCandidate.Ratio
	}

	return User, nil
}

//获取投票数
func (t *KernMethod) GetVoters(ctx contract.KContext , name string)(map[string]*big.Int,*big.Int,int64){
	Voters := make(map[string]*big.Int)
	CandidateKey := utils.MakeCacheKey(name)
	CandidateKeyBuf, err := ctx.Get(utils.GetCacheKey(),[]byte(CandidateKey))
	CacheVoteCandidate := &utils.CacheVoteCandidate{}
	if CandidateKeyBuf == nil   {
		fmt.Printf("D__获取分红比未找到该候选人 \n")
		return nil,nil,0
	} else {
		err = json.Unmarshal(CandidateKeyBuf,CacheVoteCandidate)
		if err != nil {
			fmt.Printf("D__获取投票异常错误 \n")
			return nil,nil,0
		}
	}
	Voters = CacheVoteCandidate.VotingUser
	return Voters,CacheVoteCandidate.TotalVote,CacheVoteCandidate.Ratio
}

//获取分红比
func (t *KernMethod) GetRewardRatio(ctx contract.KContext , name string)(int64){
	CandidateKey := utils.MakeCacheKey(name)
	CandidateKeyBuf, err := ctx.Get(utils.GetCacheKey(),[]byte(CandidateKey))
	CacheVoteCandidate := &utils.CacheVoteCandidate{}
	if CandidateKeyBuf == nil   {
		fmt.Printf("D__获取分红比未找到该候选人")
		return 0
	} else {
		err = json.Unmarshal(CandidateKeyBuf,CacheVoteCandidate)
		if err != nil {
			 fmt.Printf("D__获取分红比no sender found")
			 return 0
		}
	}
	return CacheVoteCandidate.Ratio
}

func (t *KernMethod) writeCandidateTable(ctx contract.KContext,to string,ratio int64,flag bool)error{
	CandidateKey := utils.MakevoteCandidateKey(to)
	CandidateKeyBuf, err := ctx.Get(utils.GetGovernTokenBucket(),[]byte(CandidateKey))
	CandidateVote := utils.NewCandidateRatio()
	if CandidateKeyBuf == nil && !flag  {
		return fmt.Errorf("D__未找到该候选人")
	}
	if CandidateKeyBuf == nil {
		fmt.Printf("D__用户%s第一次提名\n",to)
	}else {
		err = json.Unmarshal(CandidateKeyBuf,CandidateVote)
		if err != nil {
			return fmt.Errorf("no sender found")
		}
	}
	CandidateVote.IsNominate = flag
	CandidateVote.Ratio = ratio

	//修改记录了提名人的表
	AllCandidata := "allCandidate"
	AllCandidataBuf , err := ctx.Get(utils.GetGovernTokenBucket(),[]byte(AllCandidata))
	AllCandidateTable := &utils.AllCandidate{}
	if AllCandidataBuf == nil && !flag  {
		return fmt.Errorf("D__未找到该候选人")
	}
	if AllCandidataBuf == nil {
		fmt.Printf("D__第一次记录提名表\n")
	}else {
		err = json.Unmarshal(AllCandidataBuf,AllCandidateTable)
		if err != nil {
			return fmt.Errorf("no sender found")
		}
	}
	if flag {
		if AllCandidateTable.Candidate == nil {
			AllCandidateTable.Candidate = make(map[string]string)
		}
		AllCandidateTable.Candidate[to] = to
	}else {
		delete(AllCandidateTable.Candidate,to)
	}

	//写表
	CandidateBuf , _ := json.Marshal(CandidateVote)
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(CandidateKey), CandidateBuf)
	if err != nil {
		return fmt.Errorf("D__更新提名表错误,update sender's balance")
	}

	AllCandidataBuf2, _ := json.Marshal(AllCandidateTable)
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(AllCandidata), AllCandidataBuf2)
	if err != nil {
		return fmt.Errorf("D__更新全局提名表错误,update sender's balance")
	}
	return nil
}

//from:投票人
//to:被投票的人
func (t *KernMethod)writeVoteTable(ctx contract.KContext,from string,to string,vote *big.Int,flag bool)error{
	toKey := utils.MakevoteCandidateKey(to)
	toKeyBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(toKey))
	if toKeyBuf == nil && !flag {
		//to提名的时候就会记录
		return fmt.Errorf("D__%s用户未提名 \n",to)
	}
	CandidateVote := utils.NewCandidateRatio()
	err = json.Unmarshal(toKeyBuf,CandidateVote)
	if toKeyBuf == nil {
		fmt.Printf("D__第一次增加\n")
	}
	if flag {
		//总票数增加
		CandidateVote.TotalVote.Add(CandidateVote.TotalVote, vote)
		fmt.Printf("D__打印总票数： %d \n",CandidateVote.TotalVote.Int64())
		//投票人的票数也增加
		value, ok := CandidateVote.VotingUser[from]
		if ok {
			value.Add(value, vote)
			fmt.Printf("D__打印投票总数数： %d \n",value.Int64())
		} else {
			if CandidateVote.VotingUser == nil {
				CandidateVote.VotingUser = make(map[string]*big.Int)
			}
			CandidateVote.VotingUser[from] = vote
		}
	}else {
		//总票数减少
		CandidateVote.TotalVote.Sub(CandidateVote.TotalVote, vote)
		//投票人的票数也减少
		value, ok := CandidateVote.VotingUser[from]
		if ok {
			value.Sub(value, vote)
			if value.Int64() < 0 {
				return fmt.Errorf("D__撤销票数不足 \n")
			}
		} else {
			return fmt.Errorf("D__异常错误，未找到此投票用户")
		}
	}

	////修改另一张表from
	FromCandidateVote := utils.NewCandidateRatio()
	fromKey := utils.MakevoteCandidateKey(from)
	fromKeyBuf, err := ctx.Get(utils.GetGovernTokenBucket(), []byte(fromKey))
	if fromKeyBuf == nil && !flag  {
		return fmt.Errorf("D__异常错误，取消投票未找到该投票人")
	}
	if fromKeyBuf == nil {
		fmt.Printf("D__用户%s第一次投票 \n",from)
		if FromCandidateVote.MyVoting == nil {
			FromCandidateVote.MyVoting= make(map[string]*big.Int)
		}
		FromCandidateVote.MyVoting[to] = vote
	}else {
		err = json.Unmarshal(fromKeyBuf,FromCandidateVote)
		if err != nil {
			return fmt.Errorf("no sender found")
		}
		if FromCandidateVote.MyVoting == nil {
			if !flag{
				return fmt.Errorf("D__取消投票异常，票数不存在 \n")
			}
			FromCandidateVote.MyVoting= make(map[string]*big.Int)
			FromCandidateVote.MyVoting[to] = vote
		}else {
			if flag {
				FromCandidateVote.MyVoting[to].Add(FromCandidateVote.MyVoting[to], vote)
			} else {
				FromCandidateVote.MyVoting[to].Sub(FromCandidateVote.MyVoting[to], vote)
				if FromCandidateVote.MyVoting[to].Int64() < 0 {
					return fmt.Errorf("D__撤销票数不足 \n")
				}
			}
		}
	}
	//else {
	//	err = json.Unmarshal(fromKeyBuf,FromCandidateVote)
	//	if err != nil {
	//		return fmt.Errorf("no sender found")
	//	}
	//	FromCandidateVote.MyVoting[to].Add(FromCandidateVote.MyVoting[to],vote)
	//}
	//if !flag {
	//	FromCandidateVote.MyVoting[to].Sub(FromCandidateVote.MyVoting[to],vote)
	//}

	//开始写表
	//更新from表
	fromBuf, _ :=json.Marshal(FromCandidateVote)
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(fromKey), fromBuf)
	if err != nil {
		return fmt.Errorf("D__更新from表错误,update sender's balance")
	}
	//更新to表
	toBuf , _ :=json.Marshal(CandidateVote)
	err = ctx.Put(utils.GetGovernTokenBucket(), []byte(toKey), toBuf)
	if err != nil {
		return fmt.Errorf("D__更新to表错误,update sender's balance")
	}
	return nil
}

