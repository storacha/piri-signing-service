package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/filecoin-services/go/eip712"
)

// CreateDataSetRequest represents the request payload for creating a dataset
type CreateDataSetRequest struct {
	ClientDataSetId string                 `json:"clientDataSetId"`
	Payee           string                 `json:"payee"`
	Metadata        []eip712.MetadataEntry `json:"metadata"`
}

// AddPiecesRequest represents the request payload for adding pieces
type AddPiecesRequest struct {
	ClientDataSetId string                   `json:"clientDataSetId"`
	FirstAdded      string                   `json:"firstAdded"`
	PieceData       []string                 `json:"pieceData"` // hex-encoded bytes
	Metadata        [][]eip712.MetadataEntry `json:"metadata"`
}

// SchedulePieceRemovalsRequest represents the request payload for scheduling piece removals
type SchedulePieceRemovalsRequest struct {
	ClientDataSetId string   `json:"clientDataSetId"`
	PieceIds        []string `json:"pieceIds"`
}

// DeleteDataSetRequest represents the request payload for deleting a dataset
type DeleteDataSetRequest struct {
	ClientDataSetId string `json:"clientDataSetId"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status"`
	Signer string `json:"signer"`
}

// SigningService defines the interface for PDP operation signing.
type OperationSigner interface {
	// SignCreateDataSet signs a CreateDataSet operation
	SignCreateDataSet(dataSet *big.Int, payee common.Address, metadata []eip712.MetadataEntry) (*eip712.AuthSignature, error)

	// SignAddPieces signs an AddPieces operation
	SignAddPieces(dataSet *big.Int, firstAdded *big.Int, pieceData [][]byte, metadata [][]eip712.MetadataEntry) (*eip712.AuthSignature, error)

	// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation
	SignSchedulePieceRemovals(dataSet *big.Int, pieceIds []*big.Int) (*eip712.AuthSignature, error)

	// SignDeleteDataSet signs a DeleteDataSet operation
	SignDeleteDataSet(dataSet *big.Int) (*eip712.AuthSignature, error)
}
