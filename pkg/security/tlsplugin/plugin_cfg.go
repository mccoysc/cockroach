// Copyright 2026 The Cockroach Authors.
//
// Use of this software is governed by the CockroachDB Software License
// included in the /LICENSE file.

package tlsplugin

import "github.com/cockroachdb/errors"

// ConnType identifies the business-logic call site that triggered a TLS
// handshake. It is forwarded to every hook via tls_conn_info_t.conn_type so
// the plugin can apply per-context policy.
type ConnType uint8

const (
	// ConnTypeServerRPC is set when the gRPC/SQL server accepts an inbound
	// connection (node.crt / ca.crt path).
	ConnTypeServerRPC ConnType = 1

	// ConnTypeServerUI is set when the Admin UI HTTPS server accepts an
	// inbound connection (ui.crt path).
	ConnTypeServerUI ConnType = 2

	// ConnTypeClientNode is set when this node dials another node over gRPC
	// using the node client certificate.
	ConnTypeClientNode ConnType = 3

	// ConnTypeClientTenant is set when a SQL tenant server dials a KV node
	// using the tenant client certificate.
	ConnTypeClientTenant ConnType = 4

	// ConnTypeClientUI is set when the Admin UI reverse-proxy HTTP client
	// connects to a backend.
	ConnTypeClientUI ConnType = 5

	// ConnTypeClientRPC is set when a CLI command or other RPC client dials
	// a CockroachDB server using a user client certificate (e.g. root.crt).
	ConnTypeClientRPC ConnType = 6
)

// TLSPluginConfig configures an external shared library that overrides
// TLS certificate provisioning and/or peer verification.
//
// The config is entirely optional. When base.Config.TLSPlugin is nil the
// standard CockroachDB certificate-manager path is used unchanged.
//
// Plugin hooks and file-based certs can be configured simultaneously: if a
// hook returns CRDB_TLS_FALLBACK, CockroachDB falls back to the file-based
// CA/certificate/key loaded from --certs-dir. If no fallback is configured
// the connection is aborted.
//
// CLI flags:
//
//	--tls-plugin-so           path to the shared library (.so)
//	--tls-plugin-get-cert     symbol name for HOOK 1 (optional)
//	--tls-plugin-verify-cert  symbol name for HOOK 2 (optional)
//
// Effect on certificate file requirements:
//
//	get-cert configured    => node.crt and node.key are not required on disk
//	verify-cert configured => ca.crt is not required on disk
//	both configured        => --certs-dir may be absent entirely
type TLSPluginConfig struct {
	// SoPath is the filesystem path of the shared library to dlopen.
	SoPath string `yaml:"so-path"`

	// Functions names the exported C symbols to resolve in the library.
	// See pkg/security/tlsplugin/abi.h for the required C signatures.
	Functions struct {
		// GetCert names the symbol implementing crdb_tls_get_cert_fn.
		// When empty, the standard certificate manager supplies the cert.
		GetCert string `yaml:"get-cert"`

		// VerifyCert names the symbol implementing crdb_tls_verify_cert_fn.
		// When empty, standard x509 chain validation is used.
		VerifyCert string `yaml:"verify-cert"`
	} `yaml:"functions"`
}

// Validate returns an error if the configuration is self-inconsistent.
// A nil receiver is valid (means "no plugin").
func (c *TLSPluginConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.SoPath == "" {
		return errors.New("tls-plugin: so-path must not be empty")
	}
	if c.Functions.GetCert == "" && c.Functions.VerifyCert == "" {
		return errors.New("tls-plugin: at least one of " +
			"--tls-plugin-get-cert or --tls-plugin-verify-cert must be specified")
	}
	return nil
}

// SkipNodeCert reports whether node.crt/node.key are not required on disk
// (because the plugin provides the local certificate). If cert files are
// present they are loaded and used as a fallback when the hook returns
// CRDB_TLS_FALLBACK.
// Safe to call on a nil receiver (returns false).
func (c *TLSPluginConfig) SkipNodeCert() bool {
	return c != nil && c.Functions.GetCert != ""
}

// SkipCACert reports whether ca.crt is not required on disk (because the
// plugin performs peer verification itself). If a CA file is present it is
// loaded and used as a fallback when the hook returns CRDB_TLS_FALLBACK.
// Safe to call on a nil receiver (returns false).
func (c *TLSPluginConfig) SkipCACert() bool {
	return c != nil && c.Functions.VerifyCert != ""
}

// SkipCertsDir reports whether --certs-dir may be absent entirely.
// True only when both node cert and CA cert are fully handled by the plugin.
func (c *TLSPluginConfig) SkipCertsDir() bool {
	return c.SkipNodeCert() && c.SkipCACert()
}
