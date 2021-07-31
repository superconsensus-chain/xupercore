package propose

import (
	pb "github.com/superconsensus-chain/xupercore/protos"
)

type ProposeManager interface {
	GetProposalByID(proposalID string) (*pb.Proposal, error)
}
