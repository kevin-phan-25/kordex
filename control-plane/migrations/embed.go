// Package migrations owns the ordered, immutable database migrations.
package migrations

import "embed"

// Files is embedded so the runtime image needs no source tree.
//
//go:embed *.sql
var Files embed.FS
