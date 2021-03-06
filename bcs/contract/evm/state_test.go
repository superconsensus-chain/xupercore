package evm

import (
	"testing"

	"github.com/hyperledger/burrow/crypto"

	"github.com/superconsensus-chain/xupercore/kernel/contract/bridge"
)

func TestNewStateManager(t *testing.T) {

	st := newStateManager(&bridge.Context{
		ContractName: "contractName",
		Method:       "initialize",
	})

	st.UpdateAccount(nil)

	st.RemoveAccount(crypto.Address{})
}
