package client

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/filecoin-services/go/eip712"
	"github.com/storacha/go-libstoracha/capabilities/pdp/sign"
	"github.com/storacha/go-ucanto/client"
	"github.com/storacha/go-ucanto/core/dag/blockstore"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/core/invocation"
	"github.com/storacha/go-ucanto/core/ipld"
	"github.com/storacha/go-ucanto/core/receipt"
	"github.com/storacha/go-ucanto/core/result"
	fdm "github.com/storacha/go-ucanto/core/result/failure/datamodel"
	ucan_http "github.com/storacha/go-ucanto/transport/http"
	"github.com/storacha/go-ucanto/ucan"
)

// Client uses UCAN invocations to request a remote signing service to sign PDP operations.
type Client struct {
	Connection client.Connection
}

type clientConfig struct {
	httpClient *http.Client
}

type Option func(*clientConfig)

func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = client
	}
}

// New creates a new client for the signing service.
func New(serviceID ucan.Principal, serviceURL string, options ...Option) (*Client, error) {
	cfg := clientConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	endpoint, err := url.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing signing service URL: %w", err)
	}
	channel := ucan_http.NewChannel(endpoint, ucan_http.WithClient(cfg.httpClient))
	conn, err := client.NewConnection(serviceID, channel)
	if err != nil {
		return nil, fmt.Errorf("creating signing service connection: %w", err)
	}
	return &Client{conn}, nil
}

// SignCreateDataSet signs a CreateDataSet operation via UCAN invocation
func (c *Client) SignCreateDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	payee common.Address,
	metadata []eip712.MetadataEntry,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	inv, err := sign.DataSetCreate.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.DataSetCreateCaveats{
			DataSet:  dataSet,
			Payee:    payee,
			Metadata: fromEIP712MetadataEntries(metadata),
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.DataSetCreateAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

// SignAddPieces signs an AddPieces operation via UCAN invocation
func (c *Client) SignAddPieces(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	firstAdded *big.Int,
	pieceData [][]byte,
	metadata [][]eip712.MetadataEntry,
	proofs [][]receipt.AnyReceipt,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	proofLinks := make([][]ipld.Link, 0, len(proofs))
	for _, ps := range proofs {
		links := make([]ipld.Link, 0, len(ps))
		for _, r := range ps {
			links = append(links, r.Root().Link())
		}
		proofLinks = append(proofLinks, links)
	}

	metaModel := make([]sign.Metadata, 0, len(metadata))
	for _, m := range metadata {
		metaModel = append(metaModel, fromEIP712MetadataEntries(m))
	}

	inv, err := sign.PiecesAdd.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.PiecesAddCaveats{
			DataSet:    dataSet,
			FirstAdded: firstAdded,
			PieceData:  pieceData,
			Metadata:   metaModel,
			Proofs:     proofLinks,
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.PiecesAddAbility, err)
	}

	for _, ps := range proofs {
		for _, r := range ps {
			for b, err := range r.Export() {
				if err != nil {
					return nil, fmt.Errorf("iterating blocks in receipt %s: %w", r.Root().Link(), err)
				}
				if err := inv.Attach(b); err != nil {
					return nil, fmt.Errorf("attaching block %s: %w", b.Link(), err)
				}
			}
		}
	}

	return execInvocation(ctx, c.Connection, inv)
}

// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation via UCAN invocation
func (c *Client) SignSchedulePieceRemovals(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	pieceIds []*big.Int,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	inv, err := sign.PiecesRemoveSchedule.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.PiecesRemoveScheduleCaveats{
			DataSet: dataSet,
			Pieces:  pieceIds,
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.PiecesRemoveScheduleAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

// SignDeleteDataSet signs a DeleteDataSet operation via UCAN invocation
func (c *Client) SignDeleteDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	inv, err := sign.DataSetDelete.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.DataSetDeleteCaveats{
			DataSet: dataSet,
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.DataSetDeleteAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

func execInvocation(ctx context.Context, conn client.Connection, inv invocation.Invocation) (*eip712.AuthSignature, error) {
	xres, err := client.Execute(ctx, []invocation.Invocation{inv}, conn)
	if err != nil {
		return nil, fmt.Errorf("executing %s: %w", inv.Capabilities()[0].Can(), err)
	}
	rcptLink, ok := xres.Get(inv.Link())
	if !ok {
		return nil, fmt.Errorf("missing receipt for invocation: %s", inv.Link())
	}
	blocks, err := blockstore.NewBlockReader(blockstore.WithBlocksIterator(xres.Blocks()))
	if err != nil {
		return nil, fmt.Errorf("reading agent message blocks: %w", err)
	}
	rcpt, err := receipt.NewAnyReceipt(rcptLink, blocks)
	if err != nil {
		return nil, fmt.Errorf("creating receipt: %w", err)
	}
	return result.MatchResultR2(
		rcpt.Out(),
		func(o ipld.Node) (*eip712.AuthSignature, error) {
			sig, err := sign.AuthSignatureReader.Read(o)
			if err != nil {
				return nil, fmt.Errorf("reading signature: %w", err)
			}
			eipSig := eip712.AuthSignature(sig)
			return &eipSig, nil
		},
		func(x ipld.Node) (*eip712.AuthSignature, error) {
			signErr, err := sign.SignErrorReader.Read(x)
			if err != nil {
				return nil, fdm.Bind(x)
			}
			return nil, signErr
		},
	)
}

func fromEIP712MetadataEntries(entries []eip712.MetadataEntry) sign.Metadata {
	meta := sign.Metadata{
		Keys:   make([]string, 0, len(entries)),
		Values: make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		meta.Keys = append(meta.Keys, e.Key)
		meta.Values[e.Key] = e.Value
	}
	return meta
}
