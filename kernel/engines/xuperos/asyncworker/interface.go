package asyncworker

import "github.com/superconsensus-chain/xupercore/kernel/engines/xuperos/common"

type AsyncWorker interface {
	RegisterHandler(contract string, event string, handler func(ctx common.TaskContext) error)
}
