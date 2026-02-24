// Copyright 2026 The Cockroach Authors.
//
// Use of this software is governed by the CockroachDB Software License
// included in the /LICENSE file.

package tlsplugin

import (
	"testing"

	"github.com/cockroachdb/cockroach/pkg/util/leaktest"
	"github.com/stretchr/testify/require"
)

// makeCfg is a helper to build a TLSPluginConfig with the given function names,
// avoiding Go's restriction on anonymous-struct-with-tags literals.
func makeCfg(soPath, getCert, verifyCert string) *TLSPluginConfig {
	c := &TLSPluginConfig{SoPath: soPath}
	c.Functions.GetCert = getCert
	c.Functions.VerifyCert = verifyCert
	return c
}

func TestTLSPluginConfigValidate(t *testing.T) {
	defer leaktest.AfterTest(t)()

	tests := []struct {
		name        string
		cfg         *TLSPluginConfig
		expectedErr string
	}{
		{
			name: "nil config is valid",
			cfg:  nil,
		},
		{
			name:        "missing so-path",
			cfg:         &TLSPluginConfig{},
			expectedErr: "so-path must not be empty",
		},
		{
			name:        "so-path set but no function names",
			cfg:         makeCfg("/p.so", "", ""),
			expectedErr: "at least one of",
		},
		{
			name: "get-cert only is valid",
			cfg:  makeCfg("/p.so", "my_get_cert", ""),
		},
		{
			name: "verify-cert only is valid",
			cfg:  makeCfg("/p.so", "", "my_verify_cert"),
		},
		{
			name: "both functions configured",
			cfg:  makeCfg("/p.so", "my_get_cert", "my_verify_cert"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSPluginConfigSkip(t *testing.T) {
	defer leaktest.AfterTest(t)()

	tests := []struct {
		name             string
		cfg              *TLSPluginConfig
		expectedSkipNode bool
		expectedSkipCA   bool
		expectedSkipDir  bool
	}{
		{
			name: "nil config skips nothing",
			cfg:  nil,
		},
		{
			name:             "get-cert only skips node cert",
			cfg:              makeCfg("/p.so", "fn", ""),
			expectedSkipNode: true,
		},
		{
			name:           "verify-cert only skips CA cert",
			cfg:            makeCfg("/p.so", "", "fn"),
			expectedSkipCA: true,
		},
		{
			name:             "both functions skip node cert, CA cert, and certs-dir",
			cfg:              makeCfg("/p.so", "fn1", "fn2"),
			expectedSkipNode: true,
			expectedSkipCA:   true,
			expectedSkipDir:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedSkipNode, tc.cfg.SkipNodeCert())
			require.Equal(t, tc.expectedSkipCA, tc.cfg.SkipCACert())
			require.Equal(t, tc.expectedSkipDir, tc.cfg.SkipCertsDir())
		})
	}
}

func TestConnTypeConstants(t *testing.T) {
	defer leaktest.AfterTest(t)()

	// All constants must be distinct and non-zero (zero is reserved for "unknown").
	consts := []ConnType{
		ConnTypeServerRPC,
		ConnTypeServerUI,
		ConnTypeClientNode,
		ConnTypeClientTenant,
		ConnTypeClientUI,
		ConnTypeClientRPC,
	}
	names := []string{
		"ConnTypeServerRPC",
		"ConnTypeServerUI",
		"ConnTypeClientNode",
		"ConnTypeClientTenant",
		"ConnTypeClientUI",
		"ConnTypeClientRPC",
	}

	seen := make(map[ConnType]string)
	for i, c := range consts {
		require.NotZero(t, c, "%s must be non-zero", names[i])
		if prev, ok := seen[c]; ok {
			t.Errorf("duplicate ConnType value %d: %s and %s", c, prev, names[i])
		}
		seen[c] = names[i]
	}
}
