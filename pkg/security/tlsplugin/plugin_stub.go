// Copyright 2026 The Cockroach Authors.
//
// Use of this software is governed by the CockroachDB Software License
// included in the /LICENSE file.

// Plugin stub for non-Linux platforms. The shared-library loading path
// (dlopen/dlsym) is not available outside Linux; on those platforms the
// TLSPlugin type still exists but Load always returns an error.

//go:build !linux

package tlsplugin

import (
	"crypto/tls"

	"github.com/cockroachdb/errors"
)

// TLSPlugin is a loaded instance of an external TLS plugin shared library.
// On non-Linux platforms loading is unsupported; this type is present only
// to keep the rest of the codebase compilable.
type TLSPlugin struct{}

// Load returns an error on non-Linux platforms.
func Load(cfg *TLSPluginConfig) (*TLSPlugin, error) {
	if cfg == nil {
		return nil, nil
	}
	return nil, errors.New("tlsplugin: external TLS plugins are only supported on Linux")
}

// InjectIntoTLSConfig is a no-op on non-Linux platforms.
func (p *TLSPlugin) InjectIntoTLSConfig(_ *tls.Config, _ ConnType) {}
