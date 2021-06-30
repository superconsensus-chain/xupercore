package govern_token

import (
	"github.com/xuperchain/xupercore/kernel/consensus/mock"
	"math/big"
	"testing"
)

func NewM() map[string]map[string][]byte {
	a := make(map[string]map[string][]byte)
	return a
}

func NewNominateArgs() map[string][]byte {
	a := make(map[string][]byte)
	a["from"] = []byte(`TeyyPLpp9L7QAcxHangtcHTu7HUZ6iydY`)
	a["amount"] = []byte("1")
	a["lock_type"] = []byte("tdpos")
	a["to"] = []byte("dpzuVdosQrF2kmzumhVeFQZa1aYcdgFpN")
	a["ratio"] = []byte("30")
	return a
}

func TestRun(t *testing.T){


	test := new(KernMethod)
	fakeCtx := mock.NewFakeKContext(NewNominateArgs(), NewM())
	from := "TeyyPLpp9L7QAcxHangtcHTu7HUZ6iydY"
	to := "dpzuVdosQrF2kmzumhVeFQZa1aYcdgFpN"
	amountVote:= big.NewInt(30)
	//err := test.writeVoteTable(fakeCtx,from,to,amountVote,true)
	//err = test.writeVoteTable(fakeCtx,from,to,amountVote,true)
	//err = test.writeVoteTable(fakeCtx,from,to,amountVote,true)
	//
	//err = test.writeVoteTable(fakeCtx,from,to,amountVote,false)
	//err = test.writeVoteTable(fakeCtx,from,to,amountVote,false)

	err := test.writeCandidateTable(fakeCtx,from,amountVote.Int64(),true)
	err = test.writeCandidateTable(fakeCtx,from,amountVote.Int64(),false)
	err = test.writeCandidateTable(fakeCtx,from,amountVote.Int64(),false)
	err = test.writeCandidateTable(fakeCtx,from,amountVote.Int64(),true)

	err = test.writeVoteTable(fakeCtx,to,from,amountVote,true)
	err = test.writeVoteTable(fakeCtx,to,from,amountVote,true)
	err = test.writeVoteTable(fakeCtx,from,from,amountVote,true)

	err = test.writeVoteTable(fakeCtx,to,from,amountVote,false)

	err = test.UpdateCacheTable(fakeCtx)
	//_, err = test.FreezeTokens(fakeCtx)
	//_, err = test.FreezeTokens(fakeCtx)
	if err != nil {
		t.Error("runNominateCandidate error1.", "err", err)
		return
	}
}