package tdpos

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	common "github.com/superconsensus-chain/xupercore/kernel/consensus/base/common"
	cctx "github.com/superconsensus-chain/xupercore/kernel/consensus/context"
)

const (
	MAXSLEEPTIME        = 1000
	MAXMAPSIZE          = 1000
	MAXHISPROPOSERSSIZE = 100

	contractNominateCandidate = "nominateCandidate"
	contractRevokeCandidate   = "revokeNominate"
	contractVote              = "voteCandidate"
	contractRevokeVote        = "revokeVote"
	contractGetTdposInfos     = "getTdposInfos"

	tdposBucket   = "$tdpos"
	xposBucket    = "$xpos"
	nominateKey   = "nominate"
	voteKeyPrefix = "vote_"
	revokeKey     = "revoke"

	NOMINATETYPE = "nominate"
	VOTETYPE     = "vote"

	fee = 1000
)

var (
	invalidProposerErr = errors.New("Invalid proposer.")
	invalidTermErr     = errors.New("Invalid term.")
	timeoutBlockErr    = errors.New("New block is out of date.")

	MinerSelectErr   = errors.New("Node isn't a miner, calculate error.")
	EmptyValidors    = errors.New("Current validators is empty.")
	NotValidContract = errors.New("Cannot get valid res with contract.")
	InvalidQC        = errors.New("QC struct is invalid.")

	proposerNotEnoughErr = errors.New("Term publish proposer num less than config.")
	heightTooLow         = errors.New("The target height is lower than 4.")

	tooLowHeight      = errors.New("TipHeight < 3, use init parameters.")
	nominateAddrErr   = errors.New("Addr in nominate candidate tx can not be empty.")
	nominateUrlErr    = errors.New("NetUrl in nominate candidate tx can not be empty.")
	emptyVoteAddrErr  = errors.New("Addr in vote candidate tx can not be empty.")
	voteNominateErr   = errors.New("Addr in vote candidate hasn't been nominated.")
	amountErr         = errors.New("Amount in contract can not be empty.")
	authErr           = errors.New("Candidate has not authenticated your submission.")
	repeatNominateErr = errors.New("The candidate had been nominate.")
	emptyNominateKey  = errors.New("No valid candidate key when revoke.")
	notFoundErr       = errors.New("Value not found, please check your input parameters.")
	scheduleErr       = errors.New("minerScheduling overflow")
)

// tdpos ?????????????????????
type tdposConfig struct {
	Version int64 `json:"version,omitempty"`
	// ??????????????????????????????
	ProposerNum int64 `json:"proposer_num"`
	// ????????????
	Period int64 `json:"period"`
	// ???????????????????????????
	AlternateInterval int64 `json:"alternate_interval"`
	// ?????????????????????
	TermInterval int64 `json:"term_interval"`
	// ???????????????????????????????????????
	BlockNum int64 `json:"block_num"`
	// ????????????
	VoteUnitPrice *big.Int `json:"vote_unit_price"`
	// ????????????
	InitTimestamp int64 `json:"timestamp"`
	// ??????????????????????????????????????????
	InitProposer map[string][]string `json:"init_proposer"`
	EnableBFT    map[string]bool     `json:"bft_config,omitempty"`
}

func (tp *tdposConsensus) needSync() bool {
	tipBlock := tp.election.ledger.GetTipBlock()
	if tipBlock.GetHeight() == 0 {
		return true
	}
	if string(tipBlock.GetProposer()) == string(tp.election.address) {
		return false
	}
	return true
}

// unmarshalTdposConfig ??????xpoaconfig
func unmarshalTdposConfig(input []byte) (*tdposConfig, error) {
	// ??????????????????????????????????????????string??????????????????????????????
	// ?????????????????????????????????
	xconfig, err := buildConfigs(input)
	if err != nil {
		return nil, err
	}
	return xconfig, nil
}

func buildConfigs(input []byte) (*tdposConfig, error) {
	// ?????????interface{}
	consCfg := make(map[string]interface{})
	err := json.Unmarshal(input, &consCfg)
	if err != nil {
		return nil, err
	}

	// assemble consensus config
	tdposCfg := &tdposConfig{}

	// int64????????????
	int64Map := map[string]int64{
		"version":            0,
		"proposer_num":       0,
		"period":             0,
		"alternate_interval": 0,
		"term_interval":      0,
		"block_num":          0,
		"timestamp":          0,
	}
	for k, _ := range int64Map {
		if _, ok := consCfg[k]; !ok {
			if k == "version" {
				continue
			}
			return nil, fmt.Errorf("marshal consensus config failed key %s unset", k)
		}

		value, err := strconv.ParseInt(consCfg[k].(string), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("marshal consensus config failed key %s set error", k)
		}
		int64Map[k] = value
	}
	tdposCfg.Version = int64Map["version"]
	tdposCfg.ProposerNum = int64Map["proposer_num"]
	tdposCfg.Period = int64Map["period"]
	tdposCfg.AlternateInterval = int64Map["alternate_interval"]
	tdposCfg.TermInterval = int64Map["term_interval"]
	tdposCfg.BlockNum = int64Map["block_num"]
	tdposCfg.InitTimestamp = int64Map["timestamp"]

	// ????????????????????????
	voteUnitPrice := big.NewInt(0)
	if _, ok := voteUnitPrice.SetString(consCfg["vote_unit_price"].(string), 10); !ok {
		return nil, fmt.Errorf("vote_unit_price set error")
	}
	tdposCfg.VoteUnitPrice = voteUnitPrice

	type tempStruct struct {
		InitProposer map[string][]string `json:"init_proposer"`
		EnableBFT    map[string]bool     `json:"bft_config,omitempty"`
	}
	var temp tempStruct
	err = json.Unmarshal(input, &temp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal to temp struct failed.err:%v", err)
	}
	tdposCfg.InitProposer = temp.InitProposer
	tdposCfg.EnableBFT = temp.EnableBFT

	return tdposCfg, nil
}

func ParseConsensusStorage(block cctx.BlockInterface) (interface{}, error) {
	b, err := block.GetConsensusStorage()
	if err != nil {
		return nil, err
	}
	justify, err := common.ParseOldQCStorage(b)
	if err != nil {
		return nil, err
	}
	return justify, nil
}

// ?????????????????????????????????
type termBallots struct {
	Address string
	Ballots int64
}

type termBallotsSlice []*termBallots

func (tv termBallotsSlice) Len() int {
	return len(tv)
}

func (tv termBallotsSlice) Swap(i, j int) {
	tv[i], tv[j] = tv[j], tv[i]
}

func (tv termBallotsSlice) Less(i, j int) bool {
	if tv[j].Ballots == tv[i].Ballots {
		return tv[j].Address < tv[i].Address
	}
	return tv[j].Ballots < tv[i].Ballots
}
