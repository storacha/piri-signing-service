package handlers

import (
	"github.com/storacha/filecoin-services/go/eip712"
	"github.com/storacha/go-libstoracha/capabilities/pdp/sign"
)

func toEIP712MetadataEntries(m sign.Metadata) []eip712.MetadataEntry {
	meta := make([]eip712.MetadataEntry, 0, len(m.Values))
	for _, k := range m.Keys {
		v := m.Values[k]
		meta = append(meta, eip712.MetadataEntry{Key: k, Value: v})
	}
	return meta
}
