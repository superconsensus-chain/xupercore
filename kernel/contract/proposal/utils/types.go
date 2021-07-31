package utils

import (
	"encoding/json"
	"math/big"
)

const (
	GovernTokenTypeOrdinary = "ordinary"
	GovernTokenTypeTDPOS    = "tdpos"

	ProposalStatusVoting              = "voting"
	ProposalStatusCancelled           = "cancelled"
	ProposalStatusRejected            = "rejected"
	ProposalStatusPassed              = "passed"
	ProposalStatusCompletedAndFailure = "completed_failure"
	ProposalStatusCompletedAndSuccess = "completed_success"
)

const (
	GovernTokenKernelContract = "$govern_token"
	ProposalKernelContract    = "$proposal"
	TimerTaskKernelContract   = "$timer_task"
	TDPOSKernelContract       = "$tdpos"
	XPOSKernelContract        = "$xpos"
)

// Govern Token Balance
// TotalBalance = AvailableBalance + LockedBalance
// 目前包括tdpos和oridinary两种场景
// 用户的可转账余额是min(AvailableBalances)
type GovernTokenBalance struct {
	TotalBalance  *big.Int            `json:"total_balance"`
	LockedBalance map[string]*big.Int `json:"locked_balances"`
}

//投票提名记录表(普通用户这是这张表，只是部分数据没有而已)
type CandidateRatio struct {
	//总票数
	TotalVote *big.Int            	`json:"total_vote"`
	//分红比率
	Ratio int64					  	`json:"ratio"`
	//投票的人
	VotingUser map[string]*big.Int 	`json:"voting_user"`
	//是否是提名人(取消此提名人后数据不能删除，通过标志位修改)
	IsNominate bool					`json:"is_nominate"`
	//我投票的人
	MyVoting map[string]*big.Int	`json:"my_voting"`
}

//缓存表，产块分红读取这个
type CacheVoteCandidate struct {
	//分红比率
	Ratio int64					  	`json:"ratio"`
	//投票的人
	VotingUser map[string]*big.Int 	`json:"voting_user"`
	//总票数
	TotalVote *big.Int            	`json:"total_vote"`
}

//纪录所有提名人，每轮开始的时候用于更新缓存表
type AllCandidate struct {
	Candidate map[string]string 	`json:"candidate"`
}

// Proposal
type Proposal struct {
	Args    map[string]interface{} `json:"args"`
	Trigger *TriggerDesc           `json:"trigger"`

	VoteAmount *big.Int `json:"vote_amount"`
	Status     string   `json:"status"`
	Proposer   string   `json:"proposer"`
}

// TriggerDesc is the description to trigger a event used by proposal
type TriggerDesc struct {
	Height   int64                  `json:"height"`
	Module   string                 `json:"module"`
	Contract string                 `json:"contract"`
	Method   string                 `json:"method"`
	Args     map[string]interface{} `json:"args"`
}

func NewGovernTokenBalance() *GovernTokenBalance {
	balance := &GovernTokenBalance{
		TotalBalance:  big.NewInt(0),
		LockedBalance: make(map[string]*big.Int),
	}

	balance.LockedBalance[GovernTokenTypeOrdinary] = big.NewInt(0)
	balance.LockedBalance[GovernTokenTypeTDPOS] = big.NewInt(0)

	return balance
}

func NewCandidateRatio() *CandidateRatio{
	CandidateRatio := &CandidateRatio{
		TotalVote:  	big.NewInt(0),
		Ratio:			0,
	}
	return CandidateRatio
}

// Parse
func Parse(proposalStr string) (*Proposal, error) {
	proposal := &Proposal{}
	err := json.Unmarshal([]byte(proposalStr), proposal)
	if err != nil {
		return nil, err
	}
	return proposal, nil
}

// UnParse
func UnParse(proposal *Proposal) ([]byte, error) {
	proposalBuf, err := json.Marshal(proposal)
	if err != nil {
		return nil, err
	}
	return proposalBuf, nil
}
