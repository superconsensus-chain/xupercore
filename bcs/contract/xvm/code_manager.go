package xvm

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/superconsensus-chain/xupercore/kernel/contract/bridge"
	"github.com/superconsensus-chain/xupercore/protos"
	"github.com/xuperchain/xvm/compile"
	"github.com/xuperchain/xvm/exec"
	"golang.org/x/sync/singleflight"
)

type compileFunc func([]byte, string) error
type makeExecCodeFunc func(libpath string) (exec.Code, error)

type contractCode struct {
	ContractName string
	ExecCode     exec.Code
	Desc         protos.WasmCodeDesc
}

type codeManager struct {
	basedir      string
	rundir       string
	cachedir     string
	compileCode  compileFunc
	makeExecCode makeExecCodeFunc

	makeCacheLock singleflight.Group

	mutex sync.Mutex // protect codes
	codes map[string]*contractCode
}

func newCodeManager(basedir string, compile compileFunc, makeExec makeExecCodeFunc) (*codeManager, error) {
	runDirFull := filepath.Join(basedir, "var", "run")
	// clean all contract.so file in the run dir
	os.RemoveAll(runDirFull)
	cacheDirFull := filepath.Join(basedir, "var", "cache")
	if err := os.MkdirAll(runDirFull, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cacheDirFull, 0755); err != nil {
		return nil, err
	}

	return &codeManager{
		basedir:      basedir,
		rundir:       runDirFull,
		cachedir:     cacheDirFull,
		compileCode:  compile,
		makeExecCode: makeExec,
		codes:        make(map[string]*contractCode),
	}, nil
}

func codeDescEqual(a, b *protos.WasmCodeDesc) bool {
	return bytes.Equal(a.GetDigest(), b.GetDigest())
}

func (c *codeManager) lookupMemCache(name string, desc *protos.WasmCodeDesc) (*contractCode, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	ccode, ok := c.codes[name]
	if !ok {
		return nil, false
	}
	if codeDescEqual(&ccode.Desc, desc) {
		return ccode, true
	}
	return nil, false
}

func (c *codeManager) makeMemCache(name, libpath string, desc *protos.WasmCodeDesc) (*contractCode, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// ?????????????????????????????????????????????????????????so???????????????????????????
	tmpfile := fmt.Sprintf("%s-%d-%d.so", name, time.Now().UnixNano(), rand.Int()%10000)
	libpathFull := filepath.Join(c.rundir, tmpfile)
	err := cpfile(libpathFull, libpath)
	if err != nil {
		return nil, err
	}

	execCode, err := c.makeExecCode(libpathFull)
	if err != nil {
		return nil, err
	}
	code := &contractCode{
		ContractName: name,
		ExecCode:     execCode,
		Desc:         *desc,
	}
	runtime.SetFinalizer(code, func(c *contractCode) {
		c.ExecCode.Release()
	})
	c.codes[name] = code

	return code, nil
}

func fileExists(fpath string) bool {
	stat, err := os.Stat(fpath)
	if err == nil && !stat.IsDir() {
		return true
	}
	return false
}

func (c *codeManager) lookupDiskCache(name string, desc *protos.WasmCodeDesc) (string, bool) {
	descpath := filepath.Join(c.basedir, name, "code.desc")
	libpath := filepath.Join(c.basedir, name, "code.so")
	if !fileExists(descpath) || !fileExists(libpath) {
		return "", false
	}
	var localDesc protos.WasmCodeDesc
	descbuf, err := ioutil.ReadFile(descpath)
	if err != nil {
		return "", false
	}
	err = json.Unmarshal(descbuf, &localDesc)
	if err != nil {
		return "", false
	}
	if !codeDescEqual(&localDesc, desc) ||
		localDesc.GetVmCompiler() != compile.Version {
		return "", false
	}
	return libpath, true
}

func (c *codeManager) makeDiskCache(name string, desc *protos.WasmCodeDesc, codebuf []byte) (string, error) {
	basedir := filepath.Join(c.basedir, name)
	descpath := filepath.Join(basedir, "code.desc")
	libpath := filepath.Join(basedir, "code.so")

	err := os.MkdirAll(basedir, 0700)
	if err != nil {
		return "", err
	}

	err = c.compileCode(codebuf, libpath)
	if err != nil {
		return "", err
	}
	localDesc := *desc
	localDesc.VmCompiler = compile.Version
	descbuf, _ := json.Marshal(&localDesc)
	err = ioutil.WriteFile(descpath, descbuf, 0600)
	if err != nil {
		os.RemoveAll(basedir)
		return "", err
	}
	return libpath, nil
}

func (c *codeManager) GetExecCode(name string, cp bridge.ContractCodeProvider) (*contractCode, error) {
	desc, err := cp.GetContractCodeDesc(name)
	if err != nil {
		return nil, err
	}
	execCode, ok := c.lookupMemCache(name, desc)
	if ok {
		// log.Debug("contract code hit memory cache", "contract", name)
		return execCode, nil
	}

	// Only allow one goroutine make disk and memory cache at given contract name
	// other goroutine will block on the same contract name.
	icode, err, _ := c.makeCacheLock.Do(name, func() (interface{}, error) {
		defer c.makeCacheLock.Forget(name)
		// ??????pending???Do??????goroutine???Do??????????????????????????????memory cache
		// ??????????????????Do???????????????Forget???????????????????????????goroutine?????????Do??????,
		// ????????????goroutine????????????loopupMemCache???????????????Do???????????????????????????????????????cache???
		// ?????????????????????????????????????????????????????????????????????
		// ????????????double check??????????????????cache
		execCode, ok := c.lookupMemCache(name, desc)
		if ok {
			return execCode, nil
		}
		libpath, ok := c.lookupDiskCache(name, desc)
		if !ok {
			// log.Debug("contract code need make disk cache", "contract", name)
			codebuf, err := cp.GetContractCode(name)
			if err != nil {
				return nil, err
			}
			libpath, err = c.makeDiskCache(name, desc, codebuf)
			if err != nil {
				return nil, err
			}
		} else {
			// log.Debug("contract code hit disk cache", "contract", name)
		}
		return c.makeMemCache(name, libpath, desc)
	})
	if err != nil {
		return nil, err
	}
	return icode.(*contractCode), nil
}

func (c *codeManager) RemoveCode(name string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.codes, name)
	os.RemoveAll(filepath.Join(c.basedir, name))
}

// not used now
func makeCacheId(desc *protos.WasmCodeDesc) string {
	h := sha1.New()
	h.Write(desc.GetDigest())
	h.Write([]byte(compile.Version))
	return hex.EncodeToString(h.Sum(nil))
}
