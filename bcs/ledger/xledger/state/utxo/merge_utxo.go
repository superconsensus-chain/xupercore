package utxo

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/golang/protobuf/proto"

	pb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	"github.com/superconsensus-chain/xupercore/protos"
)

func (uv *UtxoVM) SelectUtxosBySize(fromAddr string, needLock, excludeUnconfirmed bool) ([]*protos.TxInput, [][]byte, *big.Int, error) {
	uv.log.Trace("start to merge utxos", "address", fromAddr)

	// Total amount selected
	amount := big.NewInt(0)
	maxTxSizePerBlock, _ := uv.metaHandle.MaxTxSizePerBlock()
	maxTxSize := big.NewInt(int64(maxTxSizePerBlock / 2))
	willLockKeys := make([][]byte, 0)
	txInputs := []*protos.TxInput{}
	txInputSize := int64(0)

	// same as the logic of SelectUTXO
	uv.clearExpiredLocks()

	addrPrefix := fmt.Sprintf("%s%s_", pb.UTXOTablePrefix, fromAddr)
	it := uv.ldb.NewIteratorWithPrefix([]byte(addrPrefix))
	defer it.Release()

	for it.Next() {
		key := append([]byte{}, it.Key()...)
		utxoItem := new(UtxoItem)
		// 反序列化utxoItem
		uErr := utxoItem.Loads(it.Value())
		if uErr != nil {
			uv.log.Warn("load utxo failed, skipped", "key", key)
			continue
		}
		// check if the utxo item has been frozen
		if utxoItem.FrozenHeight > uv.ledger.GetMeta().GetTrunkHeight() || utxoItem.FrozenHeight == -1 {
			uv.log.Debug("utxo still frozen, skipped", "key", key)
			continue
		}
		// lock utxo to be selected
		if needLock {
			if uv.tryLockKey(key) {
				willLockKeys = append(willLockKeys, key)
			} else {
				uv.log.Debug("can not lock the utxo key, conflict", "key", key)
				continue
			}
		} else if uv.isLocked(key) {
			// If the utxo has been locked
			uv.log.Debug("utxo locked, skipped", "key", key)
			continue
		}

		realKey := bytes.Split(key[len(pb.UTXOTablePrefix):], []byte("_"))
		refTxid, _ := hex.DecodeString(string(realKey[1]))

		if excludeUnconfirmed { //必须依赖已经上链的tx的UTXO
			isOnChain := uv.ledger.IsTxInTrunk(refTxid)
			if !isOnChain {
				if needLock {
					uv.UnlockKey(key)
				}
				continue
			}
		}
		offset, _ := strconv.Atoi(string(realKey[2]))
		// build a tx input
		txInput := &protos.TxInput{
			RefTxid:      refTxid,
			RefOffset:    int32(offset),
			FromAddr:     []byte(fromAddr),
			Amount:       utxoItem.Amount.Bytes(),
			FrozenHeight: utxoItem.FrozenHeight,
		}

		txInputs = append(txInputs, txInput)
		amount.Add(amount, utxoItem.Amount)
		txInputSize += int64(proto.Size(txInput))

		// check size
		txInputSize := big.NewInt(txInputSize)
		if txInputSize.Cmp(maxTxSize) == 1 {
			txInputs = txInputs[:len(txInputs)-1]
			amount.Sub(amount, utxoItem.Amount)
			if needLock {
				uv.UnlockKey(key)
			}
			break
		} else {
			continue
		}
	}
	if it.Error() != nil {
		return nil, nil, nil, it.Error()
	}

	return txInputs, willLockKeys, amount, nil
}
