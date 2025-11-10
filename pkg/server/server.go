package server

import (
	"fmt"

	logging "github.com/ipfs/go-log/v2"
	"github.com/storacha/go-libstoracha/capabilities/pdp/sign"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/server"
	"github.com/storacha/piri-signing-service/pkg/server/handlers"
	"github.com/storacha/piri-signing-service/pkg/types"
)

var log = logging.Logger("pkg/server")

func New(id principal.Signer, signer types.OperationSigner) (server.ServerView[server.Service], error) {
	options := []server.Option{
		server.WithServiceMethod(
			sign.DataSetCreateAbility,
			server.Provide(sign.DataSetCreate, handlers.NewDataSetCreateHandler(id, signer)),
		),
		server.WithServiceMethod(
			sign.DataSetDeleteAbility,
			server.Provide(sign.DataSetDelete, handlers.NewDataSetDeleteHandler(id, signer)),
		),
		server.WithServiceMethod(
			sign.PiecesAddAbility,
			server.Provide(sign.PiecesAdd, handlers.NewPiecesAddHandler(id, signer)),
		),
		server.WithServiceMethod(
			sign.PiecesRemoveScheduleAbility,
			server.Provide(sign.PiecesRemoveSchedule, handlers.NewPiecesRemoveScheduleHandler(id, signer)),
		),
		server.WithErrorHandler(func(err server.HandlerExecutionError[any]) {
			l := log.With("error", err.Error())
			if s := err.Stack(); s != "" {
				l.With("stack", s)
			}
			l.Error("ucan handler execution error")
		}),
	}
	server, err := server.NewServer(id, options...)
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}
	return server, nil
}
