package leveldb

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/superconsensus-chain/xupercore/lib/storage/mstorage"
)

// Open opens an instance of LDB with parameters (ldb path and other options)
func (ldb *LDBDatabase) OpenMulti(path string, options map[string]interface{}) error {
	setDefaultOptions(options)
	cache := options["cache"].(int)
	fds := options["fds"].(int)
	dataPaths := options["dataPaths"].([]string)

	// Open the db and recover any potential corruptions
	if dataPaths == nil || len(dataPaths) == 0 {
		db, err := leveldb.OpenFile(path, &opt.Options{
			OpenFilesCacheCapacity: fds,
			BlockCacheCapacity:     cache / 2 * opt.MiB,
			WriteBuffer:            cache / 4 * opt.MiB, // Two of these are used internally
			Filter:                 filter.NewBloomFilter(10),
		})
		if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
			//db, err = leveldb.RecoverFile(path, nil)
			//RecoverFile可能造成把sst从meta注销的后果, 比如不小心把多盘配置为单盘了,后果不可逆
			return err
		}
		// (Re)check for errors and abort if opening of the db failed
		if err != nil {
			return err
		}
		ldb.fn = path
		ldb.db = db
		return nil
	}
	//多盘存储初始化
	store, err := mstorage.OpenFile(path, false, dataPaths)
	if err != nil {
		return err
	}
	db, err := leveldb.Open(store, &opt.Options{
		OpenFilesCacheCapacity: fds,
		BlockCacheCapacity:     cache / 2 * opt.MiB,
		WriteBuffer:            cache / 4 * opt.MiB, // Two of these are used internally
		Filter:                 filter.NewBloomFilter(10),
	})
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		//db, err = leveldb.Recover(store, nil)
		return err
	}
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
		return err
	}
	ldb.fn = path
	ldb.db = db
	return nil
}
