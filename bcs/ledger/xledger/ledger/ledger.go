package ledger

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/def"
	pb "github.com/superconsensus-chain/xupercore/bcs/ledger/xledger/xldgpb"
	"github.com/superconsensus-chain/xupercore/lib/cache"
	cryptoClient "github.com/superconsensus-chain/xupercore/lib/crypto/client"
	cryptoBase "github.com/superconsensus-chain/xupercore/lib/crypto/client/base"
	"github.com/superconsensus-chain/xupercore/lib/logs"
	"github.com/superconsensus-chain/xupercore/lib/storage/kvdb"
	"github.com/superconsensus-chain/xupercore/lib/timer"
	"github.com/superconsensus-chain/xupercore/lib/utils"
	"github.com/superconsensus-chain/xupercore/protos"
)

var (
	// ErrBlockNotExist is returned when a block to query not exist in specific chain
	ErrBlockNotExist = errors.New("block not exist in this chain")
	// ErrTxNotFound is returned when a transaction to query not exist in confirmed table
	ErrTxNotFound = errors.New("transaction not found")
	// ErrTxDuplicated ...
	ErrTxDuplicated = errors.New("transaction duplicated in different blocks")
	// ErrRootBlockAlreadyExist is returned when two genesis block is checked in the process of confirming block
	ErrRootBlockAlreadyExist = errors.New("this ledger already has genesis block")
	// ErrTxNotConfirmed return tx not confirmed error
	ErrTxNotConfirmed = errors.New("transaction not confirmed")
	// NumCPU returns the number of CPU cores for the current system
	NumCPU = runtime.NumCPU()
)

var (
	// MemCacheSize baseDB memory level max size
	MemCacheSize = 128 //MB
	// FileHandlersCacheSize baseDB memory file handler cache max size
	FileHandlersCacheSize = 1024 //how many opened files-handlers cached
	// DisableTxDedup ...
	DisableTxDedup = false //whether disable dedup tx before confirm
)

const (
	// RootBlockVersion for version 1
	RootBlockVersion = 0
	// BlockVersion for version 1
	BlockVersion = 1
	// BlockCacheSize block counts in lru cache
	BlockCacheSize              = 100 //block counts in lru cache
	MaxBlockSizeKey             = "MaxBlockSize"
	ReservedContractsKey        = "ReservedContracts"
	ForbiddenContractKey        = "ForbiddenContract"
	NewAccountResourceAmountKey = "NewAccountResourceAmount"
	// Irreversible block height & slide window
	IrreversibleBlockHeightKey = "IrreversibleBlockHeight"
	IrreversibleSlideWindowKey = "IrreversibleSlideWindow"
	GasPriceKey                = "GasPrice"
	GroupChainContractKey      = "GroupChainContract"
)

// Ledger define data structure of Ledger
type Ledger struct {
	// 运行上下文
	ctx            *LedgerCtx
	baseDB         kvdb.Database // 底层是一个leveldb实例，kvdb进行了包装
	metaTable      kvdb.Database // 记录区块链的根节点、高度、末端节点
	ConfirmedTable kvdb.Database // 已确认的订单表
	blocksTable    kvdb.Database // 区块表
	mutex          *sync.RWMutex
	xlog           logs.Logger     //日志库
	meta           *pb.LedgerMeta  //账本关键的元数据{genesis, tip, height}
	GenesisBlock   *GenesisBlock   //创始块
	pendingTable   kvdb.Database   //保存临时的block区块
	heightTable    kvdb.Database   //保存高度到Blockid的映射
	blockCache     *cache.LRUCache // block cache, 加速QueryBlock
	blkHeaderCache *cache.LRUCache // block header cache, 加速fetchBlock
	cryptoClient   cryptoBase.CryptoClient
	ConfirmBatch   kvdb.Batch //新增区块
}

// ConfirmStatus block status
type ConfirmStatus struct {
	Succ        bool  // 区块是否提交成功
	Split       bool  // 提交后是否发生了分叉
	Orphan      bool  // 是否是个孤儿节点
	TrunkSwitch bool  // 是否导致了主干分支切换
	Error       error //错误消息
}

// NewLedger create an empty ledger, if it already exists, open it directly
func CreateLedger(lctx *LedgerCtx, genesisCfg []byte) (*Ledger, error) {
	return newLedger(lctx, true, genesisCfg)
}

// OpenLedger open ledger which already exists
func OpenLedger(lctx *LedgerCtx) (*Ledger, error) {
	return newLedger(lctx, false, nil)
}

func newLedger(lctx *LedgerCtx, createIfMissing bool, genesisCfg []byte) (*Ledger, error) {
	ledger := &Ledger{}
	ledger.mutex = &sync.RWMutex{}

	// new kvdb instance
	storePath := lctx.EnvCfg.GenDataAbsPath(lctx.EnvCfg.ChainDir)
	storePath = filepath.Join(storePath, lctx.BCName)
	ledgDBPath := filepath.Join(storePath, def.LedgerStrgDirName)
	kvParam := &kvdb.KVParameter{
		DBPath:                ledgDBPath,
		KVEngineType:          lctx.LedgerCfg.KVEngineType,
		MemCacheSize:          MemCacheSize,
		FileHandlersCacheSize: FileHandlersCacheSize,
		OtherPaths:            lctx.LedgerCfg.OtherPaths,
		StorageType:           lctx.LedgerCfg.StorageType,
	}
	baseDB, err := kvdb.CreateKVInstance(kvParam)
	if err != nil {
		lctx.XLog.Warn("fail to open leveldb", "dbPath", ledgDBPath, "err", err)
		return nil, err
	}

	ledger.baseDB = baseDB
	ledger.metaTable = kvdb.NewTable(baseDB, pb.MetaTablePrefix)
	ledger.ConfirmedTable = kvdb.NewTable(baseDB, pb.ConfirmedTablePrefix)
	ledger.blocksTable = kvdb.NewTable(baseDB, pb.BlocksTablePrefix)
	ledger.pendingTable = kvdb.NewTable(baseDB, pb.PendingBlocksTablePrefix)
	ledger.heightTable = kvdb.NewTable(baseDB, pb.BlockHeightPrefix)
	ledger.xlog = lctx.XLog
	ledger.meta = &pb.LedgerMeta{}
	ledger.blockCache = cache.NewLRUCache(BlockCacheSize)
	ledger.blkHeaderCache = cache.NewLRUCache(BlockCacheSize)
	ledger.ConfirmBatch = baseDB.NewBatch()
	metaBuf, metaErr := ledger.metaTable.Get([]byte(""))
	emptyLedger := false
	if metaErr != nil && def.NormalizedKVError(metaErr) == def.ErrKVNotFound && createIfMissing {
		//说明是新创建的账本
		metaBuf, pbErr := proto.Marshal(ledger.meta)
		if pbErr != nil {
			lctx.XLog.Warn("marshal meta fail", "pb_err", pbErr)
			return nil, pbErr
		}
		writeErr := ledger.metaTable.Put([]byte(""), metaBuf)
		if writeErr != nil {
			lctx.XLog.Warn("write meta_table fail", "write_err", writeErr)
			return nil, writeErr
		}
		emptyLedger = true
	} else {
		if metaErr != nil {
			lctx.XLog.Warn("unexpected kv error", "meta_err", metaErr)
			return nil, metaErr
		}
		pbErr := proto.Unmarshal(metaBuf, ledger.meta)
		if pbErr != nil {
			return nil, pbErr
		}
	}
	lctx.XLog.Info("ledger meta", "genesis_block", utils.F(ledger.meta.RootBlockid), "tip_block",
		utils.F(ledger.meta.TipBlockid), "trunk_height", ledger.meta.TrunkHeight)

	// 加载genesis config
	gErr := ledger.loadGenesisBlock(emptyLedger, genesisCfg)
	if gErr != nil {
		lctx.XLog.Warn("failed to load genesis block", "g_err", gErr)
		return nil, gErr
	}

	// 根据创世块牌照加密类型实例化加密组件
	cryptoType := ledger.GenesisBlock.GetConfig().GetCryptoType()
	crypto, err := cryptoClient.CreateCryptoClient(cryptoType)
	if err != nil {
		lctx.XLog.Warn("failed to create crypto client", "cryptoType", cryptoType, "err", err)
		return nil, fmt.Errorf("failed to create crypto client")
	}
	ledger.cryptoClient = crypto

	return ledger, nil
}

// Close close an instance of ledger
func (l *Ledger) Close() {
	l.baseDB.Close()
}

// GetMeta returns meta info of Ledger, such as genesis block ID, current block height, tip block ID
func (l *Ledger) GetMeta() *pb.LedgerMeta {
	return l.meta
}

// GetLDB returns the instance of underlying of kv db
func (l *Ledger) GetLDB() kvdb.Database {
	return l.baseDB
}

func (l *Ledger) loadGenesisBlock(isEmptyLedger bool, genesisCfg []byte) error {
	if !isEmptyLedger {
		// 非空账本，从创世块加载
		if len(l.meta.RootBlockid) == 0 {
			return ErrBlockNotExist
		}
		rootIb, err := l.queryBlock(l.meta.RootBlockid, true)
		if err != nil {
			return err
		}

		var coinbaseTx *pb.Transaction
		for _, tx := range rootIb.Transactions {
			if tx.Coinbase {
				coinbaseTx = tx
				break
			}
		}
		if coinbaseTx == nil {
			return fmt.Errorf("find coinbase tx failed from root block")
		}

		genesisCfg = coinbaseTx.GetDesc()
	}

	gb, gErr := NewGenesisBlock(genesisCfg)
	if gErr != nil {
		return gErr
	}

	l.GenesisBlock = gb
	return nil
}

// FormatRootBlock format genesis block
func (l *Ledger) FormatRootBlock(txList []*pb.Transaction) (*pb.InternalBlock, error) {
	l.xlog.Info("begin format genesis block")
	block := &pb.InternalBlock{Version: RootBlockVersion}
	block.Transactions = txList
	block.TxCount = int32(len(txList))
	block.MerkleTree = MakeMerkleTree(txList)
	if len(block.MerkleTree) > 0 {
		block.MerkleRoot = block.MerkleTree[len(block.MerkleTree)-1]
	}
	var err error
	block.Blockid, err = MakeBlockID(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// FormatBlock format normal block
func (l *Ledger) FormatBlock(txList []*pb.Transaction,
	proposer []byte, ecdsaPk *ecdsa.PrivateKey, /*矿工的公钥私钥*/
	timestamp int64, curTerm int64, curBlockNum int64,
	preHash []byte, utxoTotal *big.Int) (*pb.InternalBlock, error) {
	return l.formatBlock(txList, proposer, ecdsaPk, timestamp, curTerm, curBlockNum, preHash, 0, utxoTotal, true, nil, nil, 0)
}

// FormatMinerBlock format block for miner
func (l *Ledger) FormatMinerBlock(txList []*pb.Transaction,
	proposer []byte, ecdsaPk *ecdsa.PrivateKey, /*矿工的公钥私钥*/
	timestamp int64, curTerm int64, curBlockNum int64,
	preHash []byte, targetBits int32, utxoTotal *big.Int,
	qc *pb.QuorumCert, failedTxs map[string]string, blockHeight int64) (*pb.InternalBlock, error) {
	return l.formatBlock(txList, proposer, ecdsaPk, timestamp, curTerm, curBlockNum, preHash, targetBits, utxoTotal, true, qc, failedTxs, blockHeight)
}

// FormatFakeBlock format fake block for contract pre-execution without signing
func (l *Ledger) FormatFakeBlock(txList []*pb.Transaction,
	proposer []byte, ecdsaPk *ecdsa.PrivateKey, /*矿工的公钥私钥*/
	timestamp int64, curTerm int64, curBlockNum int64,
	preHash []byte, utxoTotal *big.Int, blockHeight int64) (*pb.InternalBlock, error) {
	return l.formatBlock(txList, proposer, ecdsaPk, timestamp, curTerm, curBlockNum, preHash, 0, utxoTotal, false, nil, nil, blockHeight)
}

/*
内存中格式化一个区块
*/
func (l *Ledger) formatBlock(txList []*pb.Transaction,
	proposer []byte, ecdsaPk *ecdsa.PrivateKey, /*矿工的公钥私钥*/
	timestamp int64, curTerm int64, curBlockNum int64,
	preHash []byte, targetBits int32, utxoTotal *big.Int, needSign bool,
	qc *pb.QuorumCert, failedTxs map[string]string, blockHeight int64) (*pb.InternalBlock, error) {
	l.xlog.Info("begin format block", "preHash", utils.F(preHash))
	//编译的环境变量指定
	block := &pb.InternalBlock{Version: BlockVersion}
	block.Transactions = txList
	block.TxCount = int32(len(txList))
	block.Timestamp = timestamp
	block.Proposer = proposer
	block.CurTerm = curTerm
	block.CurBlockNum = curBlockNum
	block.TargetBits = targetBits
	block.Justify = qc
	block.Height = blockHeight
	jsPk, pkErr := l.cryptoClient.GetEcdsaPublicKeyJsonFormatStr(ecdsaPk)
	if pkErr != nil {
		return nil, pkErr
	}
	block.Pubkey = []byte(jsPk)
	block.PreHash = preHash
	if !needSign {
		fakeTree := make([][]byte, len(txList))
		for i, tx := range txList {
			fakeTree[i] = tx.Txid
		}
		block.MerkleTree = fakeTree
	} else {
		block.MerkleTree = MakeMerkleTree(txList)
	}
	if failedTxs != nil {
		block.FailedTxs = failedTxs
	} else {
		block.FailedTxs = map[string]string{}
	}
	if len(block.MerkleTree) > 0 {
		block.MerkleRoot = block.MerkleTree[len(block.MerkleTree)-1]
	}
	var err error
	block.Blockid, err = MakeBlockID(block)
	if err != nil {
		return nil, err
	}

	if len(preHash) > 0 && needSign {
		block.Sign, err = l.cryptoClient.SignECDSA(ecdsaPk, block.Blockid)
	}
	if err != nil {
		return nil, err
	}
	return block, nil
}

//保存一个区块（只包括区块头）
// 注：只是打包到一个leveldb batch write对象中
func (l *Ledger) saveBlock(block *pb.InternalBlock, batchWrite kvdb.Batch) error {
	blockBuf, pbErr := proto.Marshal(block)
	l.blkHeaderCache.Add(string(block.Blockid), block)
	if pbErr != nil {
		l.xlog.Warn("marshal block fail", "pbErr", pbErr)
		return pbErr
	}
	batchWrite.Put(append([]byte(pb.BlocksTablePrefix), block.Blockid...), blockBuf)
	if block.InTrunk {
		sHeight := []byte(fmt.Sprintf("%020d", block.Height))
		batchWrite.Put(append([]byte(pb.BlockHeightPrefix), sHeight...), block.Blockid)
	}
	return nil
}

//根据blockid获取一个Block, 只包含区块头
func (l *Ledger) fetchBlock(blockid []byte) (*pb.InternalBlock, error) {
	blkInCache, cacheHit := l.blkHeaderCache.Get(string(blockid))
	if cacheHit {
		return blkInCache.(*pb.InternalBlock), nil
	}
	blockBuf, findErr := l.blocksTable.Get(blockid)
	if def.NormalizedKVError(findErr) == def.ErrKVNotFound {
		l.xlog.Warn("block can not be found", "findErr", findErr, "blockid", utils.F(blockid))
		return nil, findErr
	} else if findErr != nil {
		l.xlog.Warn("unkonw error", "findErr", findErr)
		return nil, findErr
	}
	block := &pb.InternalBlock{}
	pbErr := proto.Unmarshal(blockBuf, block)
	if pbErr != nil {
		l.xlog.Warn("block may corrupt", "pbErr", pbErr)
		return nil, pbErr
	}
	return block, nil
}

//当发生主干切换后，确保最长路径上的block的tx的blockid指向它
func (l *Ledger) correctTxsBlockid(blockID []byte, batchWrite kvdb.Batch) error {
	block, err := l.queryBlock(blockID, true)
	if err != nil {
		return err
	}
	for _, tx := range block.Transactions {
		if !bytes.Equal(tx.Blockid, blockID) {
			l.xlog.Warn("correct blockid of tx", "txid", utils.F(tx.Txid),
				"old_blockid", utils.F(tx.Blockid), "new_blockid", utils.F(
					blockID))
			tx.Blockid = blockID
			pbTxBuf, err := proto.Marshal(tx)
			if err != nil {
				l.xlog.Warn("marshal trasaction failed when confirm block", "err", err)
				return err
			}
			batchWrite.Put(append([]byte(pb.ConfirmedTablePrefix), tx.Txid...), pbTxBuf)
		}
	}
	return nil
}

//处理分叉
// P---->P---->P---->P (old tip)
//       |
//       +---->Q---->Q--->NewTip
// 处理完后，会返回分叉点的block
func (l *Ledger) handleFork(oldTip []byte, newTipPre []byte, nextHash []byte, batchWrite kvdb.Batch) (*pb.InternalBlock, error) {
	p := oldTip
	q := newTipPre
	for !bytes.Equal(p, q) {
		pBlock, pErr := l.fetchBlock(p)
		if pErr != nil {
			return nil, pErr
		}
		pBlock.InTrunk = false
		pBlock.NextHash = []byte{} //next_hash表示是主干上的下一个blockid，所以分支上的这个属性清空
		qBlock, qErr := l.fetchBlock(q)
		if qErr != nil {
			return nil, qErr
		}
		qBlock.InTrunk = true
		cerr := l.correctTxsBlockid(qBlock.Blockid, batchWrite)
		if cerr != nil {
			return nil, cerr
		}
		qBlock.NextHash = nextHash
		nextHash = q
		p = pBlock.PreHash
		q = qBlock.PreHash
		saveErr := l.saveBlock(pBlock, batchWrite)
		if saveErr != nil {
			return nil, saveErr
		}
		saveErr = l.saveBlock(qBlock, batchWrite)
		if saveErr != nil {
			return nil, saveErr
		}
	}
	splitBlock, qErr := l.fetchBlock(q)
	if qErr != nil {
		return nil, qErr
	}
	splitBlock.InTrunk = true
	splitBlock.NextHash = nextHash
	saveErr := l.saveBlock(splitBlock, batchWrite)
	if saveErr != nil {
		return nil, saveErr
	}
	return splitBlock, nil
}


////设置奖励分配
func (l *Ledger)AssignRewards(address string,blockAward *big.Int) *big.Int {

	award := big.NewInt(0)

	//读term表l
	toTable := "tdpos_term"
	termTable := &protos.TermTable{}
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(toTable))
	if kvErr != nil {
		return award
	}
	parserErr := proto.Unmarshal(PbTxBuf, termTable)
	if parserErr != nil {
		//	fmt.Printf("D__读TermTable表错误\n")
		return award
	}
	if termTable.NewCycle == true {
		fmt.Printf("D__校验发现是新的周期\n")
		return award
	}

	//读缓存表
	key := "cache_" + address
	table := &protos.CacheVoteCandidate{}
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(key))
	if kvErr != nil {
		return award
	}
	parserErr = proto.Unmarshal(PbTxBuf, table)
	if parserErr != nil{
		fmt.Printf("D__校验分配奖励读UserReward表错误\n")
		return award
	}
	ratData := table.Ratio
	award.Mul(blockAward,big.NewInt(ratData)).Div(award,big.NewInt(100))
	return award
}

// IsValidTx valid transactions of coinbase in block
func (l *Ledger) IsValidTx(idx int, tx *pb.Transaction, block *pb.InternalBlock) bool {
	if tx.Coinbase { //检查系统奖励交易的合法性
		if len(tx.TxOutputs) < 1 {
			l.xlog.Warn("invalid length of coinbase tx outputs, when ConfirmBlock", "len", len(tx.TxOutputs))
			return false
		}
		//交易奖励的金额是否符合策略?
		awardTarget := l.GenesisBlock.CalcAward(block.Height)
		//获取奖励比
		remainAward := l.AssignRewards(string(block.Proposer),awardTarget)
		blockAward := big.NewInt(0)
		blockAward.Sub(awardTarget,remainAward)
		fmt.Printf("DT__当前奖励比: %s \n", blockAward.String())
		fmt.Printf("DT__当前高度： %d , 出块人 : %s \n",block.Height,string(block.Proposer))

		amountBytes := tx.TxOutputs[0].Amount
		awardN := big.NewInt(0)
		awardN.SetBytes(amountBytes)
		fmt.Printf("DT__awardN奖励: %s \n",awardN.String())
		if awardN.Cmp(blockAward) != 0 {
			l.xlog.Warn("invalid block award found", "award", awardN.String(), "target", awardTarget.String())
			return false
		}
	}
	return true
}

// UpdateBlockChainData modify tx which txid is txid
func (l *Ledger) UpdateBlockChainData(txid string, ptxid string, publickey string, sign string, height int64) error {
	if txid == "" || ptxid == "" {
		return fmt.Errorf("invalid update blockchaindata requests")
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.xlog.Info("ledger UpdateBlockChainData", "tx", txid, "ptxid", ptxid)

	rawTxid, err := hex.DecodeString(txid)
	tx, err := l.QueryTransaction(rawTxid)
	if err != nil {
		l.xlog.Warn("ledger UpdateBlockChainData query tx error")
		return fmt.Errorf("ledger UpdateBlockChainData query tx error")
	}

	tx.ModifyBlock = &pb.ModifyBlock{
		Marked:          true,
		EffectiveTxid:   ptxid,
		EffectiveHeight: height,
		PublicKey:       publickey,
		Sign:            sign,
	}
	tx.Desc = []byte("")
	tx.TxOutputsExt = []*protos.TxOutputExt{}

	pbTxBuf, err := proto.Marshal(tx)
	if err != nil {
		l.xlog.Warn("marshal trasaction failed when UpdateBlockChainData", "err", err)
		return err
	}
	l.ConfirmedTable.Put(tx.Txid, pbTxBuf)

	l.xlog.Info("Update BlockChainData success", "txid", hex.EncodeToString(tx.Txid))
	return nil
}

func (l *Ledger) parallelCheckTx(txs []*pb.Transaction, block *pb.InternalBlock) (map[string]bool, map[string][]byte) {
	parallelLevel := NumCPU
	if len(txs) < parallelLevel {
		parallelLevel = len(txs)
	}
	ch := make(chan *pb.Transaction)
	mu := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	txExist := map[string]bool{}
	txData := map[string][]byte{}
	total := len(txs)
	wg.Add(total)
	for i := 0; i <= parallelLevel; i++ {
		go func() {
			for tx := range ch {
				tx.Blockid = block.Blockid
				pbTxBuf, err := proto.Marshal(tx)
				if err != nil {
					l.xlog.Warn("marshal trasaction failed when confirm block", "err", err)
					mu.Lock()
					txData[string(tx.Txid)] = nil
					mu.Unlock()
				} else {
					mu.Lock()
					txData[string(tx.Txid)] = pbTxBuf
					mu.Unlock()
				}
				if !DisableTxDedup || !block.InTrunk {
					hasTx, _ := l.ConfirmedTable.Has(tx.Txid)
					mu.Lock()
					txExist[string(tx.Txid)] = hasTx
					mu.Unlock()
				}
				wg.Done()
			}
		}()
	}
	for _, tx := range txs {
		ch <- tx
	}
	wg.Wait()
	close(ch)
	return txExist, txData
}

// ConfirmBlock submit a block to ledger
func (l *Ledger) ConfirmBlock(block *pb.InternalBlock, isRoot bool) ConfirmStatus {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	blkTimer := timer.NewXTimer()
	l.xlog.Info("start to confirm block", "blockid", utils.F(block.Blockid), "txCount", len(block.Transactions))
	var confirmStatus ConfirmStatus
	dummyTransactions := []*pb.Transaction{}
	realTransactions := block.Transactions // 真正的交易转存到局部变量
	block.Transactions = dummyTransactions // block表不保存transaction详情

	batchWrite := l.ConfirmBatch
	batchWrite.Reset()
	newMeta := proto.Clone(l.meta).(*pb.LedgerMeta)
	splitHeight := newMeta.TrunkHeight
	if isRoot { //确认创世块
		if block.PreHash != nil && len(block.PreHash) > 0 {
			confirmStatus.Succ = false
			l.xlog.Warn("genesis block shoud has no prehash")
			return confirmStatus
		}
		if len(l.meta.RootBlockid) > 0 {
			confirmStatus.Succ = false
			confirmStatus.Error = ErrRootBlockAlreadyExist
			l.xlog.Warn("already hash genesis block")
			return confirmStatus
		}
		newMeta.RootBlockid = block.Blockid
		newMeta.TrunkHeight = 0 //代表主干上块的最大高度
		newMeta.TipBlockid = block.Blockid
		block.InTrunk = true
		block.Height = 0 // 创世纪块是第0块
	} else { //非创世块,需要判断是在主干还是分支
		preHash := block.PreHash
		preBlock, findErr := l.fetchBlock(preHash)
		if findErr != nil {
			l.xlog.Warn("find pre block fail", "findErr", findErr)
			confirmStatus.Succ = false
			return confirmStatus
		}
		block.Height = preBlock.Height + 1 //不管是主干还是分支，height都是++
		if bytes.Equal(preBlock.Blockid, newMeta.TipBlockid) {
			//在主干上添加
			block.InTrunk = true
			preBlock.NextHash = block.Blockid
			newMeta.TipBlockid = block.Blockid
			newMeta.TrunkHeight++
			//因为改了pre_block的next_hash值，所以也要写回存储
			if !DisableTxDedup {
				saveErr := l.saveBlock(preBlock, batchWrite)
				l.blockCache.Del(string(preBlock.Blockid))
				if saveErr != nil {
					l.xlog.Warn("save block fail", "saveErr", saveErr)
					confirmStatus.Succ = false
					return confirmStatus
				}
			}
		} else {
			//在分支上
			if preBlock.Height+1 > newMeta.TrunkHeight {
				//分支要变成主干了
				oldTip := append([]byte{}, newMeta.TipBlockid...)
				newMeta.TrunkHeight = preBlock.Height + 1
				newMeta.TipBlockid = block.Blockid
				block.InTrunk = true
				splitBlock, splitErr := l.handleFork(oldTip, preBlock.Blockid, block.Blockid, batchWrite) //处理分叉
				if splitErr != nil {
					l.xlog.Warn("handle split failed", "splitErr", splitErr)
					confirmStatus.Succ = false
					return confirmStatus
				}
				splitHeight = splitBlock.Height
				confirmStatus.Split = true
				confirmStatus.TrunkSwitch = true
				l.xlog.Info("handle split successfully", "splitBlock", utils.F(splitBlock.Blockid))
			} else {
				// 添加在分支上, 对preblock没有影响
				block.InTrunk = false
				confirmStatus.Split = true
				confirmStatus.TrunkSwitch = false
				confirmStatus.Orphan = true
			}
		}
	}
	saveErr := l.saveBlock(block, batchWrite)
	blkTimer.Mark("saveHeader")
	if saveErr != nil {
		confirmStatus.Succ = false
		l.xlog.Warn("save current block fail", "saveErr", saveErr)
		return confirmStatus
	}
	// update branch head
	updateBranchErr := l.updateBranchInfo(block.Blockid, block.PreHash, block.Height, batchWrite)
	if updateBranchErr != nil {
		confirmStatus.Succ = false
		l.xlog.Warn("update branch info fail", "updateBranchErr", updateBranchErr)
		return confirmStatus
	}
	txExist, txData := l.parallelCheckTx(realTransactions, block)
	cbNum := 0
	oldBlockCache := map[string]*pb.InternalBlock{}
	for _, tx := range realTransactions {
		//在这儿解析交易存表,调用新版的接口TxOutputs不会超过4
		//理论上这儿坐过校验判断后，不会报错，目前还是写好报错码，以便调试
		if len(tx.TxInputs) >0 &&len(tx.TxOutputs) < 4 && len(tx.ContractRequests) > 0 {
			req := tx.ContractRequests[0]
			tmpReq := &InvokeRequest{
				ModuleName:   req.ModuleName,
				ContractName: req.ContractName,
				MethodName:   req.MethodName,
				Args:         map[string]string{},
			}
			for argKey, argV := range req.Args {
				tmpReq.Args[argKey] = string(argV)
			}
			if tmpReq.ModuleName == "xkernel" && tmpReq.ContractName == "$govern_token"{
				//这里有buy和sell
				switch tmpReq.MethodName {
				case "Buy":
					l.WriteFreezeTable(batchWrite,tmpReq.Args["amount"],string(tx.TxInputs[0].FromAddr),tx.Txid)
				case "Sell":
					l.WriteThawTable(batchWrite,string(tx.TxInputs[0].FromAddr),tx.Desc)
				default:
					fmt.Printf("D__解析交易存表时方法异常，异常方法名: %s \n",tmpReq.MethodName)
				}
			}
			if tmpReq.ModuleName == "xkernel" && tmpReq.ContractName == "$tdpos"{
				switch tmpReq.MethodName {
				case "nominateCandidate":
					l.WriteCandidateTable(batchWrite,string(tx.TxInputs[0].FromAddr),tmpReq.Args)
				case "revokeNominate":
					l.WriteReCandidateTable(batchWrite,string(tx.TxInputs[0].FromAddr),tmpReq.Args)
				case "voteCandidate":
					l.VoteCandidateTable(batchWrite,string(tx.TxInputs[0].FromAddr),tmpReq.Args)
				case "revokeVote":
					l.RevokeVote(batchWrite,string(tx.TxInputs[0].FromAddr),tmpReq.Args)
				default:
					fmt.Printf("D__解析tdpos交易存表时方法异常，异常方法名: %s \n",tmpReq.MethodName)
				}
			}
		}


		if tx.Coinbase {
			cbNum = cbNum + 1
		}
		if cbNum > 1 {
			confirmStatus.Succ = false
			l.xlog.Warn("The num of Coinbase tx should not exceed one when confirm block",
				"BlockID", utils.F(tx.Blockid), "Miner", string(block.Proposer))
			return confirmStatus
		}

		pbTxBuf := txData[string(tx.Txid)]
		if pbTxBuf == nil {
			confirmStatus.Succ = false
			l.xlog.Warn("marshal trasaction failed when confirm block")
			return confirmStatus
		}
		hasTx := txExist[string(tx.Txid)]
		if !hasTx {
			batchWrite.Put(append([]byte(pb.ConfirmedTablePrefix), tx.Txid...), pbTxBuf)
		} else {
			//confirm表已经存在这个交易了，需要检查一下是否存在多个主干block包含同样trasnaction的情况
			oldPbTxBuf, _ := l.ConfirmedTable.Get(tx.Txid)
			oldTx := &pb.Transaction{}
			parserErr := proto.Unmarshal(oldPbTxBuf, oldTx)
			if parserErr != nil {
				confirmStatus.Succ = false
				confirmStatus.Error = parserErr
				return confirmStatus
			}
			oldBlock := &pb.InternalBlock{}
			if cachedBlk, cacheHit := oldBlockCache[string(oldTx.Blockid)]; cacheHit {
				oldBlock = cachedBlk
			} else {
				oldPbBlockBuf, blockErr := l.blocksTable.Get(oldTx.Blockid)
				if blockErr != nil {
					if def.NormalizedKVError(blockErr) == def.ErrKVNotFound {
						l.xlog.Warn("old block that contains the tx has been truncated", "txid", utils.F(tx.Txid), "blockid", utils.F(oldTx.Blockid))
						batchWrite.Put(append([]byte(pb.ConfirmedTablePrefix), tx.Txid...), pbTxBuf) //overwrite with newtx
						continue
					}
					confirmStatus.Succ = false
					confirmStatus.Error = blockErr
					return confirmStatus
				}
				parserErr = proto.Unmarshal(oldPbBlockBuf, oldBlock)
				if parserErr != nil {
					confirmStatus.Succ = false
					confirmStatus.Error = parserErr
					return confirmStatus
				}
				oldBlockCache[string(oldBlock.Blockid)] = oldBlock
			}
			if oldBlock.InTrunk && block.InTrunk && oldBlock.Height <= splitHeight {
				confirmStatus.Succ = false
				confirmStatus.Error = ErrTxDuplicated
				l.xlog.Warn("transaction duplicated in previous trunk block",
					"txid", utils.F(tx.Txid),
					"blockid", utils.F(oldBlock.Blockid))
				return confirmStatus
			} else if block.InTrunk {
				l.xlog.Info("change blockid of tx", "txid", utils.F(tx.Txid), "blockid", utils.F(block.Blockid))
				batchWrite.Put(append([]byte(pb.ConfirmedTablePrefix), tx.Txid...), pbTxBuf)
			}
		}
	}
	blkTimer.Mark("saveAllTxs")
	//删除pendingBlock中对应的数据
	batchWrite.Delete(append([]byte(pb.PendingBlocksTablePrefix), block.Blockid...))
	//改meta
	metaBuf, pbErr := proto.Marshal(newMeta)
	if pbErr != nil {
		l.xlog.Warn("marshal meta fail", "pbErr", pbErr)
		confirmStatus.Succ = false
		return confirmStatus
	}
	batchWrite.Put([]byte(pb.MetaTablePrefix), metaBuf)
	l.xlog.Debug("print block size when confirm block", "blockSize", batchWrite.ValueSize(), "blockid", utils.F(block.Blockid))
	kvErr := batchWrite.Write() // blocks, confirmed_transaction两张表原子写入
	blkTimer.Mark("saveToDisk")
	if kvErr != nil {
		confirmStatus.Succ = false
		confirmStatus.Error = kvErr
		l.xlog.Warn("batch write failed when confirm block", "kvErr", kvErr)
	} else {
		confirmStatus.Succ = true
		l.meta = newMeta
	}
	block.Transactions = realTransactions
	if isRoot {
		//首次confirm 创始块的时候
		lErr := l.loadGenesisBlock(false, nil)
		if lErr != nil {
			confirmStatus.Succ = false
			confirmStatus.Error = lErr
		}
	}
	l.blockCache.Add(string(block.Blockid), block)
	l.xlog.Debug("confirm block cost", "blkTimer", blkTimer.Print())
	return confirmStatus
}

// TxDesc is the description to running a contract
type TxDesc struct {
	Args   map[string]interface{} `json:"args"`
}
//申请解冻
func (l *Ledger) WriteThawTable(batch kvdb.Batch,user string,desc []byte) error {
	//解冻的总余额
	amount := big.NewInt(0)
	txDesc := &TxDesc{}
	jsErr := json.Unmarshal(desc,txDesc)
	if jsErr != nil {
		fmt.Printf("D__确认区块时解析desc错误 \n")
		return jsErr
	}
	var txids []interface{}
	switch txDesc.Args["txid"].(type) {
	case []interface{}:
		txids = txDesc.Args["txid"].([]interface{})
	default:
		return  errors.New("D__txid should be []interface{}")
	}
	//记录申请解冻金额
	//申请解冻这儿，输入的交易一定是冻结表里面的，否则报错，所以先获取该用户冻结信息
	keytalbe := "amount_" + user
	//查看用户是否冻结过
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(keytalbe))
	table := &protos.FrozenAssetsTable{}
	if(kvErr != nil){
		fmt.Printf("D__确认区块时请冻结资产再操作\n")
		return kvErr
	}else {
		parserErr := proto.Unmarshal(PbTxBuf, table)
		if parserErr != nil {
			fmt.Printf("D__确认区块时读FrozenAssetsTable表错误\n")
			return parserErr
		}
	}
	for _ , v := range txids {
		value, ok := table.FrozenDetail[v.(string)]
		if ok{
			tableValue ,_:= new(big.Int).SetString(value.Amount,10)
			amount.Add(amount,tableValue)
			//把当前冻结的放回到解冻
			tabledata := &protos.FrozenDetails{
				Height : l.GetMeta().TrunkHeight + 1 +20,
				Amount: value.Amount,
			}
			delete(table.FrozenDetail,v.(string))
			if table.ThawDetail == nil {
				table.ThawDetail = make(map[string]*protos.FrozenDetails)
			}
			table.ThawDetail[v.(string)] = tabledata
		}
	}
	pbTxBuf, err := proto.Marshal(table)
	if err != nil {
		fmt.Printf("D__确认区块时解析FrozenAssetsTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)

	//解冻内容存储至节点信息表，在出块的时候通过交易id构建退款交易
	keytalbe = "nodeinfo_" + "tdos_thaw_total_assets"
	//查看节点是否存在申请解冻的
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(keytalbe))
	NodeTable := &protos.NodeTable{}
	if(kvErr != nil) {
		fmt.Printf("D__第一次申请解冻\n", user)
	}else {
		parserErr := proto.Unmarshal(PbTxBuf, NodeTable)
		if parserErr != nil {
			fmt.Printf("D__解冻治理代币时读NodeTable表错误\n")
			return parserErr
		}
	}
	if NodeTable.NodeDetails == nil {
		NodeTable.NodeDetails = make(map[int64]*protos.NodeDetails)
	}
	NodeDetail := &protos.NodeDetail{
		Address: user,
		Amount: amount.String(),
		Height : l.GetMeta().TrunkHeight + 1 +20,

	}
	NodeDetails := &protos.NodeDetails{}
	if NodeTable.NodeDetails[NodeDetail.Height] == nil {
		//NodeTable.NodeDetails[NodeDetail.Height]
		//NodeDetails := &protos.NodeDetails{}
		NodeDetails.NodeDetail = append(NodeDetails.NodeDetail,NodeDetail )
		NodeTable.NodeDetails[NodeDetail.Height] = NodeDetails
	}else {
		NodeDetails.NodeDetail = NodeTable.NodeDetails[NodeDetail.Height].NodeDetail
		NodeDetails.NodeDetail = append(NodeDetails.NodeDetail,NodeDetail )
		NodeTable.NodeDetails[NodeDetail.Height] = NodeDetails
	}
	//NodeTable.NodeDetails[NodeDetail.Height].NodeDetail = append(NodeTable.NodeDetails[NodeDetail.Height].NodeDetail,NodeDetail )
	//写表
	pbTxBuf, err = proto.Marshal(NodeTable)
	if err != nil {
		fmt.Printf("D__解析NodeTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)

	//解冻后用户提案表治理代币减少
	keytalbe = "ballot_" + user
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(keytalbe))
	CandidateTable := &protos.CandidateRatio{}
	if(kvErr != nil){
		fmt.Printf("D__用户未投票\n",user)
		return kvErr
	}
	parserErr := proto.Unmarshal(PbTxBuf, CandidateTable)
	if parserErr != nil {
		fmt.Printf("D__解冻治理代币时读CandidateRatio表错误\n")
		return parserErr
	}
	oldAmount := big.NewInt(0)
	oldAmount.SetString(CandidateTable.TatalVote,10)
	CandidateTable.TatalVote = oldAmount.Sub(oldAmount,amount).String()

	//开始写治理投票表
	pbTxBuf, err = proto.Marshal(CandidateTable)
	if err != nil {
		fmt.Printf("D__购买治理代币时解析CandidateTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)

	//全网抵押总资产减少
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			l.xlog.Warn("D__取消提案时解析读AllCandidate表错误","parserErr",parserErr)
			return parserErr
		}
		oldAmount := big.NewInt(0)
		oldAmount.SetString(freetable.Freemonry, 10)
		freetable.Freemonry = oldAmount.Sub(oldAmount,amount).String()
	}else {
		l.xlog.Warn("btdpos_freezes_total_assets not fonud ", "kvErr", kvErr)
		return kvErr
	}
	pbTxBuf, err = proto.Marshal(freetable)
	if err != nil {
		l.xlog.Warn("D__解析AllCandidate失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), toTable...), pbTxBuf)

	//fmt.Printf("D__申请冻结表执行完毕 \n")
	return nil
}

//读治理代币表
func (l *Ledger) ReadBallotTable(user string ,table *protos.CandidateRatio )(error){
	keytable := "ballot_" + user
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(keytable))
	if(kvErr != nil) {
		return errors.New("D__读取UserBallot异常\n")
	}
	parserErr := proto.Unmarshal(PbTxBuf, table)
	if parserErr != nil  {
		return errors.New("D__读UserBallotTable表错误\n")
	}
	return nil
}

//撤销投票写表
func (l *Ledger) RevokeVote(batch kvdb.Batch,user string,Args map[string]string) error {
	CandidateTable := &protos.CandidateRatio{}
	error := l.ReadBallotTable(user,CandidateTable)
	if error != nil {
		return error
	}
	//判断票数，获取参数
	candidate := Args["candidate"]
	amount := Args["amount"]
	//撤销的投票数
	ballots := big.NewInt(0)
	ballots.SetString(amount,10)
	//此用户投票的那个账户投票数减少
	value , ok := CandidateTable.MyVoting[candidate]
	if ok {
		NewAmount := big.NewInt(0)
		NewAmount.SetString(value,10)
		value = NewAmount.Sub(NewAmount,ballots).String()
		CandidateTable.MyVoting[candidate] = value
	}
	//撤销投票后，已使用的投票数减少
	TotalAmount := big.NewInt(0)
	TotalAmount.SetString(CandidateTable.Used,10)
	CandidateTable.Used = TotalAmount.Sub(TotalAmount,ballots).String()
	//写表
	pbTxBuf, err := proto.Marshal(CandidateTable)
	if err != nil {
		return errors.New("D__解析UserBallotTable失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + user...), pbTxBuf)
	kvErr := batch.Write() //原子写入
	if kvErr != nil {
		return errors.New("D__写表错误\n ")
	}

	//读撤销投票的用户表,修改被投票的内容
	BeCandidateTable := &protos.CandidateRatio{}
	error = l.ReadBallotTable(user,BeCandidateTable)
	if error != nil {
		return error
	}
	//查找
	value , ok = BeCandidateTable.VotingUser[user]
	if ok {
		oldAmount := big.NewInt(0)
		oldAmount.SetString(value,10)
		value = oldAmount.Sub(oldAmount,ballots).String()
		BeCandidateTable.VotingUser[user] = value
	}
	//被投票的总数也减少
	BeAmount := big.NewInt(0)
	BeAmount.SetString(BeCandidateTable.BeVotedTotal,10)
	BeCandidateTable.BeVotedTotal = BeAmount.Sub(BeAmount,ballots).String()
	//写表
	pbTxBuf , err =  proto.Marshal(BeCandidateTable)
	if err != nil {
		return errors.New("D__投票写表解析BeCandidateTable失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + candidate...), pbTxBuf)
	return nil
}

//投票写表
func (l *Ledger) VoteCandidateTable(batch kvdb.Batch,user string,Args map[string]string) error {
	fmt.Printf("D__进入投票写表~~~~~~~~~~~~~~~~~~\n")
	CandidateTable := &protos.CandidateRatio{}
	error := l.ReadBallotTable(user,CandidateTable)
	if error != nil {
		return error
	}
	//判断票数，获取参数
	candidate := Args["candidate"]
	amount := Args["amount"]

	//判断票数，这儿不处理，参数校验那儿完成
	//如果之前投了此人，更新票数
	newAmount := big.NewInt(0)
	newAmount.SetString(amount,10)
	value , ok := CandidateTable.MyVoting[candidate]
	if ok {
		oldAmount := big.NewInt(0)
		oldAmount.SetString(value,10)
		value = oldAmount.Add(oldAmount,newAmount).String()
		//fmt.Printf("D__投票后当前票数: %s \n",value)
		CandidateTable.MyVoting[candidate] = value
	}else {
		if CandidateTable.MyVoting == nil {
			CandidateTable.MyVoting = make(map[string]string)
		}
		CandidateTable.MyVoting[candidate] = amount
		//fmt.Printf("D__第一次投，投票后当前票数: %s \n",value)
	}
	//已使用的投票数增加
	tableAmount := big.NewInt(0)
	tableAmount.SetString(CandidateTable.Used,10)
	CandidateTable.Used = tableAmount.Add(tableAmount,newAmount).String()
	//写表
	pbTxBuf, err := proto.Marshal(CandidateTable)
	if err != nil {
		return errors.New("D__投票写表解析CandidateRatio失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + user...), pbTxBuf)
	kvErr := batch.Write() //原子写入
	if kvErr != nil {
		return errors.New("D__写表错误\n ")
	}

	//被投的人的投票提案表更新被投票的消息
	BeCandidateTable := &protos.CandidateRatio{}
	error = l.ReadBallotTable(candidate,BeCandidateTable)
	if error != nil {
		return error
	}
	//查找
	value , ok = BeCandidateTable.VotingUser[user]
	if ok {
		oldAmount := big.NewInt(0)
		oldAmount.SetString(value,10)
		value = oldAmount.Add(oldAmount,newAmount).String()
		BeCandidateTable.VotingUser[user] = value
	}else {
		if BeCandidateTable.VotingUser == nil {
			BeCandidateTable.VotingUser = make(map[string]string)
		}
		BeCandidateTable.VotingUser[user] = amount
	}
	//被投票的总数也增加
	BeAmount := big.NewInt(0)
	BeAmount.SetString(BeCandidateTable.BeVotedTotal,10)
	BeCandidateTable.BeVotedTotal = BeAmount.Add(BeAmount,newAmount).String()
	//写表
	pbTxBuf , err =  proto.Marshal(BeCandidateTable)
	if err != nil {
		return errors.New("D__投票写表解析BeCandidateTable失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + candidate...), pbTxBuf)

	return nil
}

//撤销提案写表
func (l *Ledger) WriteReCandidateTable (batch kvdb.Batch,user string,Args map[string]string) error {
	amount := big.NewInt(0)
	//参数获取，取消的提名人
	candidate := Args["candidate"]
	//取消提名的人治理代币消耗减少
	CandidateTable := &protos.CandidateRatio{}
	//取消提名成功后，候选人信息删除
	error := l.ReadBallotTable(user,CandidateTable)
	if error != nil {
		return error
	}
	//获取取消提名人之前抵押的
	if CandidateTable.NominateDetails == nil {
		return  errors.New("D__撤销提案内容内容错误\n")
	}
	value , ok := CandidateTable.NominateDetails[candidate]
	if ok{
		amount.SetString(value.Amount,10)
	}else {
		return  errors.New("D__无法取消不是自己提名的用户\n")
	}
	oldAmount := big.NewInt(0)
	oldAmount.SetString(CandidateTable.Used,10)
	CandidateTable.Used = oldAmount.Sub(oldAmount,amount).String()
	//删除此次记录
	delete( CandidateTable.NominateDetails,candidate)
	//写表
	pbTxBuf, err := proto.Marshal(CandidateTable)
	if err != nil {
		fmt.Printf("D__取消提案时解析CandidateTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + user...), pbTxBuf)
	kvErr := batch.Write() //原子写入
	if kvErr != nil {
		return errors.New("D__写表错误\n ")
	}

	//被修改提名者信息
	beCandidateTable := &protos.CandidateRatio{}
	error = l.ReadBallotTable(candidate,beCandidateTable)
	if error != nil {
		return error
	}
	beCandidateTable.Ratio = 0
	beCandidateTable.Is_Nominate = false
	//写表
	pbTxBuf, err = proto.Marshal(beCandidateTable)
	if err != nil {
		fmt.Printf("D__取消提案时解析被修改提名者信息CandidateTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + candidate...), pbTxBuf)
	//所有提名表那删除这次提名人
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			fmt.Printf("D__取消提案时解析读AllCandidate表错误\n")
			return parserErr
		}
	}
	delete(freetable.Candidate,candidate)
	pbTxBuf, err = proto.Marshal(freetable)
	if err != nil {
		return errors.New("D__取消提案时解析AllCandidate失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), toTable...), pbTxBuf)

	return nil
}

//提案写表
func (l *Ledger) WriteCandidateTable (batch kvdb.Batch,user string,Args map[string]string) error {
	//参数获取，被提名人
	candidate := Args["candidate"]
	//参数获取，抵押的代币数
	amount := Args["amount"]
	//分红比
	ratio := Args["ratio"]

	//提名的人治理代币消耗增加
	CandidateTable := &protos.CandidateRatio{}
	//提名成功后，候选人信息加在这个里面
	nominateTable := &protos.NominateDetails{}
	error := l.ReadBallotTable(user,CandidateTable)
	if error != nil {
		return error
	}
	if CandidateTable.Used == ""{
		fmt.Printf("D__用户%s第一次消耗治理代币\n",user)
		CandidateTable.Used = "0"
	}
	newAmout := big.NewInt(0)
	newAmout.SetString(amount,10)
	oldAmount := big.NewInt(0)
	oldAmount.SetString(CandidateTable.Used,10)
	CandidateTable.Used = oldAmount.Add(oldAmount,newAmout).String()
	nominateTable.Amount = amount
	if CandidateTable.NominateDetails == nil {
		CandidateTable.NominateDetails = make(map[string]*protos.NominateDetails)
	}
	CandidateTable.NominateDetails[candidate] = nominateTable

	//写表
	pbTxBuf, err := proto.Marshal(CandidateTable)
	if err != nil {
		fmt.Printf("D__提案时解析CandidateTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + user...), pbTxBuf)
	kvErr := batch.Write() //原子写入
	if kvErr != nil {
		return errors.New("D__写表错误\n ")
	}

	//走到这儿，写被提名人的表
	ratioAmount := big.NewInt(0)
	ratioAmount.SetString(ratio,10)
	keytalbe := "ballot_" + candidate
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(keytalbe))
	beCandidateTable := &protos.CandidateRatio{}
	if(kvErr != nil){
		fmt.Printf("D__第一次提名此用户%s \n",candidate)
	}else {
		parserErr := proto.Unmarshal(PbTxBuf, beCandidateTable)
		if parserErr != nil {
			fmt.Printf("D__提案时解析读CandidateRatio表错误\n")
			return parserErr
		}
	}
	beCandidateTable.Is_Nominate = true
	beCandidateTable.Ratio = ratioAmount.Int64()
	//写表
	pbTxBuf, err = proto.Marshal(beCandidateTable)
	if err != nil {
		fmt.Printf("D__提案时解析CandidateTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), "ballot_" + candidate...), pbTxBuf)

	//在这儿记录一下所有提名人
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			fmt.Printf("D__读UtxoMetaExplorer表错误\n")
			return parserErr
		}
	}else {
		fmt.Printf("D__用户%s是第一个提案人 \n",candidate)
	}
	if freetable.Candidate == nil {
		freetable.Candidate = make(map[string]string)
		freetable.Candidate[candidate] = candidate
	}else {
		freetable.Candidate[candidate] = candidate
	}

	pbTxBuf, err = proto.Marshal(freetable)
	if err != nil {
		return errors.New("D__解析AllCandidate失败\n")
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), toTable...), pbTxBuf)
	return nil
}

//写入冻结表
func (l *Ledger)WriteFreezeTable(batch kvdb.Batch,amount string,user string,txid []byte) error {
	keytalbe := "amount_" + user
	//查看用户是否冻结过
	PbTxBuf, kvErr := l.ConfirmedTable.Get([]byte(keytalbe))
	table := &protos.FrozenAssetsTable{}
	if(kvErr != nil){
		fmt.Printf("D__用户%s第一次冻结\n",string(user))
		table.Total = "0"
	}else {
		parserErr := proto.Unmarshal(PbTxBuf, table)
		if parserErr != nil {
			fmt.Printf("D__购买治理代币时读FrozenAssetsTable表错误\n")
			return parserErr
		}
	}
	//拿取冻结的金额
	tabledata := &protos.FrozenDetails{
		Timestamp:        time.Now().UnixNano(),
	}
	if table.FrozenDetail == nil {
		table.FrozenDetail = make(map[string]*protos.FrozenDetails)
	}
	newAmount := big.NewInt(0)
	_, isAmount := newAmount.SetString(amount, 10)
	oldAmount := big.NewInt(0)
	oldAmount.SetString(table.Total,10)
	if !isAmount || newAmount.Cmp(big.NewInt(0)) == -1 {
		fmt.Printf("D__购买治理代币时解析amount失败\n")
	}
	tabledata.Amount = newAmount.String()
	table.FrozenDetail[hex.EncodeToString(txid)] = tabledata
	table.Total = oldAmount.Add(oldAmount,newAmount).String()
	//开始写表
	pbTxBuf, err := proto.Marshal(table)
	if err != nil {
		fmt.Printf("D__购买治理代币时解析FrozenAssetsTable失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)

	//用户提案表治理代币增加
	keytalbe = "ballot_" + user
	//查看用户是否之前有过
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(keytalbe))
	CandidateTable := &protos.CandidateRatio{}
	if(kvErr != nil){
		fmt.Printf("D__用户%s第一次增加治理代币\n",user)
		CandidateTable.TatalVote = amount
	}else {
		parserErr := proto.Unmarshal(PbTxBuf, CandidateTable)
		if parserErr != nil {
			fmt.Printf("D__购买治理代币时读CandidateRatio表错误\n")
			return parserErr
		}
		oldAmount := big.NewInt(0)
		oldAmount.SetString(CandidateTable.TatalVote,10)
		CandidateTable.TatalVote = oldAmount.Add(oldAmount,newAmount).String()
	}
	//开始写治理投票表
	pbTxBuf, err = proto.Marshal(CandidateTable)
	if err != nil {
		fmt.Printf("D__购买治理代币时解析CandidateTable失败\n")
		return err
	}

	batch.Put(append([]byte(pb.ConfirmedTablePrefix), keytalbe...), pbTxBuf)

	//全网抵押总资产增加
	toTable := "tdpos_freezes_total_assets"
	freetable := &protos.AllCandidate{}
	PbTxBuf, kvErr = l.ConfirmedTable.Get([]byte(toTable))
	if kvErr == nil {
		parserErr := proto.Unmarshal(PbTxBuf, freetable)
		if parserErr != nil {
			l.xlog.Warn("D__取消提案时解析读AllCandidate表错误","parserErr",parserErr)
			return parserErr
		}
		oldAmount := big.NewInt(0)
		oldAmount.SetString(freetable.Freemonry, 10)
		freetable.Freemonry = newAmount.Add(newAmount,oldAmount).String()
	}else {
		freetable.Freemonry = amount
	}
	pbTxBuf, err = proto.Marshal(freetable)
	if err != nil {
		l.xlog.Warn("D__解析AllCandidate失败\n")
		return err
	}
	batch.Put(append([]byte(pb.ConfirmedTablePrefix), toTable...), pbTxBuf)

	return nil
}

// ExistBlock check if a block exists in the ledger
func (l *Ledger) ExistBlock(blockid []byte) bool {
	exist, _ := l.blocksTable.Has(blockid)
	return exist
}

func (l *Ledger) queryBlock(blockid []byte, needBody bool) (*pb.InternalBlock, error) {
	pbBlockBuf, err := l.blocksTable.Get(blockid)
	if err != nil {
		if def.NormalizedKVError(err) == def.ErrKVNotFound {
			err = ErrBlockNotExist
		}
		return nil, err
	}
	block := &pb.InternalBlock{}
	parserErr := proto.Unmarshal(pbBlockBuf, block)
	if parserErr != nil {
		return nil, parserErr
	}
	if needBody {
		realTransactions := make([]*pb.Transaction, 0)
		for _, txid := range block.MerkleTree[:block.TxCount] {
			pbTxBuf, kvErr := l.ConfirmedTable.Get(txid)
			if kvErr != nil {
				l.xlog.Warn("tx not found", "kvErr", kvErr, "txid", utils.F(txid))
				return block, kvErr
			}
			realTx := &pb.Transaction{}
			parserErr = proto.Unmarshal(pbTxBuf, realTx)
			if parserErr != nil {
				l.xlog.Warn("tx parser err", "parserErr", parserErr)
				return block, parserErr
			}
			realTransactions = append(realTransactions, realTx)
		}
		block.Transactions = realTransactions
	}
	return block, nil
}

// QueryBlock query a block by blockID in the ledger
func (l *Ledger) QueryBlock(blockid []byte) (*pb.InternalBlock, error) {
	blkInCache, exist := l.blockCache.Get(string(blockid))
	if exist {
		l.xlog.Debug("hit queryblock cache", "blkid", utils.F(blockid))
		return blkInCache.(*pb.InternalBlock), nil
	}
	blk, err := l.queryBlock(blockid, true)
	if err != nil {
		return nil, err
	}
	l.blockCache.Add(string(blockid), blk)
	return blk, nil
}

// QueryBlockHeader query a block by blockID in the ledger and return only block header
func (l *Ledger) QueryBlockHeader(blockid []byte) (*pb.InternalBlock, error) {
	return l.queryBlock(blockid, false)
}

// HasTransaction check if a transaction exists in the ledger
func (l *Ledger) HasTransaction(txid []byte) (bool, error) {
	table := l.ConfirmedTable
	return table.Has(txid)
}

// QueryTransaction query a transaction in the ledger and return it if exist
func (l *Ledger) QueryTransaction(txid []byte) (*pb.Transaction, error) {
	table := l.ConfirmedTable
	pbTxBuf, kvErr := table.Get(txid)
	if kvErr != nil {
		if def.NormalizedKVError(kvErr) == def.ErrKVNotFound {
			return nil, ErrTxNotFound
		}
		return nil, kvErr
	}
	realTx := &pb.Transaction{}
	parserErr := proto.Unmarshal(pbTxBuf, realTx)
	if parserErr != nil {
		return nil, parserErr
	}
	return realTx, nil
}

// IsTxInTrunk check if a transaction is in trunk by transaction ID
func (l *Ledger) IsTxInTrunk(txid []byte) bool {
	var blk *pb.InternalBlock
	var err error
	table := l.ConfirmedTable
	pbTxBuf, kvErr := table.Get(txid)
	if kvErr != nil {
		return false
	}
	realTx := &pb.Transaction{}
	pbErr := proto.Unmarshal(pbTxBuf, realTx)
	if pbErr != nil {
		l.xlog.Warn("IsTxInTrunk error", "txid", utils.F(txid), "pbErr", pbErr)
		return false
	}
	blkInCache, exist := l.blockCache.Get(string(realTx.Blockid))
	if exist {
		blk = blkInCache.(*pb.InternalBlock)
	} else {
		blk, err = l.queryBlock(realTx.Blockid, false)
		if err != nil {
			l.xlog.Warn("IsTxInTrunk error", "blkid", utils.F(realTx.Blockid), "kvErr", err)
			return false
		}
	}
	return blk.InTrunk
}

// FindUndoAndTodoBlocks get blocks required to undo and todo range from curBlockid to destBlockid
func (l *Ledger) FindUndoAndTodoBlocks(curBlockid []byte, destBlockid []byte) ([]*pb.InternalBlock, []*pb.InternalBlock, error) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	undoBlocks := []*pb.InternalBlock{}
	todoBlocks := []*pb.InternalBlock{}
	if bytes.Equal(destBlockid, curBlockid) { //原地踏步的情况...
		return undoBlocks, todoBlocks, nil
	}
	rootBlockid := l.meta.RootBlockid
	oldTip, oErr := l.queryBlock(curBlockid, true)
	if oErr != nil {
		l.xlog.Warn("block not found", "blockid", utils.F(curBlockid))
		return nil, nil, oErr
	}
	newTip, nErr := l.queryBlock(destBlockid, true)
	if nErr != nil {
		l.xlog.Warn("block not found", "blockid", utils.F(destBlockid))
		return nil, nil, nErr
	}
	visited := map[string]bool{}
	undoBlocks = append(undoBlocks, oldTip)
	todoBlocks = append(todoBlocks, newTip)
	visited[string(oldTip.Blockid)] = true
	visited[string(newTip.Blockid)] = true
	var splitBlockID []byte //最近的分叉点
	for {
		oldPreHash := oldTip.PreHash
		if len(oldPreHash) > 0 && oldTip.Height >= newTip.Height {
			oldTip, oErr = l.queryBlock(oldPreHash, true)
			if oErr != nil {
				return nil, nil, oErr
			}
			if _, exist := visited[string(oldTip.Blockid)]; exist {
				splitBlockID = oldTip.Blockid //从老tip开始回溯到了分叉点
				break
			} else {
				visited[string(oldTip.Blockid)] = true
				undoBlocks = append(undoBlocks, oldTip)
			}
		}
		newPreHash := newTip.PreHash
		if len(newPreHash) > 0 && newTip.Height >= oldTip.Height {
			newTip, nErr = l.queryBlock(newPreHash, true)
			if nErr != nil {
				return nil, nil, nErr
			}
			if _, exist := visited[string(newTip.Blockid)]; exist {
				splitBlockID = newTip.Blockid //从新tip开始回溯到了分叉点
				break
			} else {
				visited[string(newTip.Blockid)] = true
				todoBlocks = append(todoBlocks, newTip)
			}
		}
		if len(oldPreHash) == 0 && len(newPreHash) == 0 {
			splitBlockID = rootBlockid // 这种情况只能从roott算了
			break
		}
	}
	//收尾工作，todo_blocks, undo_blocks 如果最后一个元素是分叉点，需要去掉
	if bytes.Equal(undoBlocks[len(undoBlocks)-1].Blockid, splitBlockID) {
		undoBlocks = undoBlocks[:len(undoBlocks)-1]
	}
	if bytes.Equal(todoBlocks[len(todoBlocks)-1].Blockid, splitBlockID) {
		todoBlocks = todoBlocks[:len(todoBlocks)-1]
	}
	return undoBlocks, todoBlocks, nil
}

// Dump dump ledger structure, block height to blockid
func (l *Ledger) Dump() ([][]string, error) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	it := l.baseDB.NewIteratorWithPrefix([]byte(pb.BlocksTablePrefix))
	defer it.Release()
	blocks := make([][]string, l.meta.TrunkHeight+1)
	for it.Next() {
		block := &pb.InternalBlock{}
		parserErr := proto.Unmarshal(it.Value(), block)
		if parserErr != nil {
			return nil, parserErr
		}
		height := block.Height
		blockid := fmt.Sprintf("{ID:%x,TxCount:%d,InTrunk:%v, Tm:%d, Miner:%s}", block.Blockid, block.TxCount, block.InTrunk, block.Timestamp/1000000000, block.Proposer)
		blocks[height] = append(blocks[height], blockid)
	}
	return blocks, nil
}

// GetGenesisBlock returns genesis block if it exists
func (l *Ledger) GetGenesisBlock() *GenesisBlock {
	if l.GenesisBlock != nil {
		return l.GenesisBlock
	}
	return nil
}

// GetIrreversibleSlideWindow return irreversible slide window
func (l *Ledger) GetIrreversibleSlideWindow() int64 {
	defaultIrreversibleSlideWindow := l.GenesisBlock.GetConfig().GetIrreversibleSlideWindow()
	return defaultIrreversibleSlideWindow
}

// GetMaxBlockSize return max block size
func (l *Ledger) GetMaxBlockSize() int64 {
	defaultBlockSize := l.GenesisBlock.GetConfig().GetMaxBlockSizeInByte()
	return defaultBlockSize
}

// GetNewAccountResourceAmount return the resource amount of new an account
func (l *Ledger) GetNewAccountResourceAmount() int64 {
	defaultNewAccountResourceAmount := l.GenesisBlock.GetConfig().GetNewAccountResourceAmount()
	return defaultNewAccountResourceAmount
}

func (l *Ledger) GetReservedContracts() ([]*protos.InvokeRequest, error) {
	return l.GenesisBlock.GetConfig().GetReservedContract()
}

func (l *Ledger) GetForbiddenContract() ([]*protos.InvokeRequest, error) {
	return l.GenesisBlock.GetConfig().GetForbiddenContract()
}

func (l *Ledger) GetGroupChainContract() ([]*protos.InvokeRequest, error) {
	return l.GenesisBlock.GetConfig().GetGroupChainContract()
}

func (l *Ledger) GetGasPrice() *protos.GasPrice {
	return l.GenesisBlock.GetConfig().GetGasPrice()
}

func (l *Ledger) GetNoFee() bool {
	return l.GenesisBlock.GetConfig().NoFee
}

// SavePendingBlock put block into pending table
func (l *Ledger) SavePendingBlock(block *pb.InternalBlock) error {
	l.xlog.Debug("begin save pending block", "blockid", utils.F(block.Blockid), "tx_count", len(block.Transactions))
	blockBuf, pbErr := proto.Marshal(block)
	if pbErr != nil {
		l.xlog.Warn("save pending block fail, because marshal block fail", "pbErr", pbErr)
		return pbErr
	}
	saveErr := l.pendingTable.Put(block.Blockid, blockBuf)
	if saveErr != nil {
		l.xlog.Warn("save pending block to ldb fail", "err", saveErr)
		return saveErr
	}
	return nil
}

// GetPendingBlock get block from pending table
func (l *Ledger) GetPendingBlock(blockID []byte) (*pb.InternalBlock, error) {
	l.xlog.Debug("get pending block", "bockid", utils.F(blockID))
	blockBuf, ldbErr := l.pendingTable.Get(blockID)
	if ldbErr != nil {
		if def.NormalizedKVError(ldbErr) != def.ErrKVNotFound { //其他kv错误
			l.xlog.Warn("get pending block fail", "err", ldbErr, "blockid", utils.F(blockID))
		} else { //不存在表里面
			l.xlog.Debug("the block not in pending blocks", "blocid", utils.F(blockID))
			return nil, ErrBlockNotExist
		}
		return nil, ldbErr
	}
	block := &pb.InternalBlock{}
	unMarshalErr := proto.Unmarshal(blockBuf, block)
	if unMarshalErr != nil {
		l.xlog.Warn("unmarshal block failed", "err", unMarshalErr)
		return nil, unMarshalErr
	}
	return block, nil
}

// QueryBlockByHeight query block by height
func (l *Ledger) QueryBlockByHeight(height int64) (*pb.InternalBlock, error) {
	sHeight := []byte(fmt.Sprintf("%020d", height))
	blockID, kvErr := l.heightTable.Get(sHeight)
	if kvErr != nil {
		if def.NormalizedKVError(kvErr) == def.ErrKVNotFound {
			return nil, ErrBlockNotExist
		}
		return nil, kvErr
	}
	return l.QueryBlock(blockID)
}

// GetBaseDB get internal db instance
func (l *Ledger) GetBaseDB() kvdb.Database {
	return l.baseDB
}

func (l *Ledger) removeBlocks(fromBlockid []byte, toBlockid []byte, batch kvdb.Batch) error {
	fromBlock, findErr := l.fetchBlock(fromBlockid)
	if findErr != nil {
		l.xlog.Warn("failed to find block", "findErr", findErr)
		return findErr
	}
	toBlock, findErr := l.fetchBlock(toBlockid)
	if findErr != nil {
		l.xlog.Warn("failed to find block", "findErr", findErr)
		return findErr
	}
	for fromBlock.Height > toBlock.Height {
		l.xlog.Info("remove block", "blockid", utils.F(fromBlock.Blockid), "height", fromBlock.Height)
		l.blkHeaderCache.Del(string(fromBlock.Blockid))
		l.blockCache.Del(string(fromBlock.Blockid))
		batch.Delete(append([]byte(pb.BlocksTablePrefix), fromBlock.Blockid...))
		if fromBlock.InTrunk {
			sHeight := []byte(fmt.Sprintf("%020d", fromBlock.Height))
			batch.Delete(append([]byte(pb.BlockHeightPrefix), sHeight...))
		}
		//iter to prev block
		fromBlock, findErr = l.fetchBlock(fromBlock.PreHash)
		if findErr != nil {
			l.xlog.Warn("failed to find prev block", "findErr", findErr)
			return nil //ignore orphan block
		}
	}
	return nil
}

// Truncate truncate ledger and set tipblock to utxovmLastID
func (l *Ledger) Truncate(utxovmLastID []byte) error {
	l.xlog.Info("start truncate ledger", "blockid", utils.F(utxovmLastID))

	// 获取账本锁
	l.mutex.Lock()
	defer l.mutex.Unlock()

	batchWrite := l.baseDB.NewBatch()
	newMeta := proto.Clone(l.meta).(*pb.LedgerMeta)
	newMeta.TipBlockid = utxovmLastID

	// 获取裁剪目标区块信息
	block, err := l.fetchBlock(utxovmLastID)
	if err != nil {
		l.xlog.Warn("failed to find utxovm last block", "err", err, "blockid", utils.F(utxovmLastID))
		return err
	}
	// 查询分支信息
	branchTips, err := l.GetBranchInfo(block.Blockid, block.Height)
	if err != nil {
		l.xlog.Warn("failed to find all branch tips", "err", err)
		return err
	}

	// 逐个分支裁剪到目标高度
	for _, branchTip := range branchTips {
		deletedBlockid := []byte(branchTip)
		// 裁剪到目标高度
		err = l.removeBlocks(deletedBlockid, block.Blockid, batchWrite)
		if err != nil {
			l.xlog.Warn("failed to remove garbage blocks", "from", utils.F(l.meta.TipBlockid),
				"to", utils.F(block.Blockid))
			return err
		}
		// 更新分支高度信息
		err = l.updateBranchInfo(block.Blockid, deletedBlockid, block.Height, batchWrite)
		if err != nil {
			l.xlog.Warn("truncate failed when calling updateBranchInfo", "err", err)
			return err
		}
	}

	newMeta.TrunkHeight = block.Height
	metaBuf, err := proto.Marshal(newMeta)
	if err != nil {
		l.xlog.Warn("failed to marshal pb meta")
		return err
	}
	batchWrite.Put([]byte(pb.MetaTablePrefix), metaBuf)
	err = batchWrite.Write()
	if err != nil {
		l.xlog.Warn("batch write failed when truncate", "err", err)
		return err
	}
	l.meta = newMeta

	l.xlog.Info("truncate blockid succeed")
	return nil
}

// VerifyBlock verify block
func (l *Ledger) VerifyBlock(block *pb.InternalBlock, logid string) (bool, error) {
	blkid, err := MakeBlockID(block)
	if err != nil {
		l.xlog.Warn("VerifyBlock MakeBlockID error", "logid", logid, "error", err)
		return false, nil
	}
	if !(bytes.Equal(blkid, block.Blockid)) {
		l.xlog.Warn("VerifyBlock equal blockid error", "logid", logid, "redo blockid", utils.F(blkid),
			"get blockid", utils.F(block.Blockid))
		return false, nil
	}

	errv := VerifyMerkle(block)
	if errv != nil {
		l.xlog.Warn("VerifyMerkle error", "logid", logid, "error", errv)
		return false, nil
	}

	k, err := l.cryptoClient.GetEcdsaPublicKeyFromJsonStr(string(block.Pubkey))
	if err != nil {
		l.xlog.Warn("VerifyBlock get ecdsa from block error", "logid", logid, "error", err)
		return false, nil
	}
	chkResult, _ := l.cryptoClient.VerifyAddressUsingPublicKey(string(block.Proposer), k)
	if chkResult == false {
		l.xlog.Warn("VerifyBlock address is not match publickey", "logid", logid)
		return false, nil
	}

	valid, err := l.cryptoClient.VerifyECDSA(k, block.Sign, block.Blockid)
	if err != nil || !valid {
		l.xlog.Warn("VerifyBlock VerifyECDSA error", "logid", logid, "error", err)
		return false, nil
	}
	return true, nil
}

// QueryBlockByTxid query block by txid after it has confirmed
func (l *Ledger) QueryBlockByTxid(txid []byte) (*pb.InternalBlock, error) {
	if exit, _ := l.HasTransaction(txid); !exit {
		return nil, ErrTxNotConfirmed
	}
	tx, err := l.QueryTransaction(txid)
	if err != nil {
		return nil, err
	}
	return l.queryBlock(tx.GetBlockid(), false)
}
