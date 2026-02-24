// Copyright 2026 The Cockroach Authors.
//
// Use of this software is governed by the CockroachDB Software License
// included in the /LICENSE file.

// Plugin is only available on Linux (uses dlopen/dlsym).
//go:build linux

package tlsplugin

/*
#cgo LDFLAGS: -ldl
#include "abi.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static void *crdb_dlopen(const char *path, char **errmsg) {
	void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!h) { *errmsg = strdup(dlerror()); }
	return h;
}

static void *crdb_dlsym(void *handle, const char *sym, char **errmsg) {
	dlerror();
	void *p = dlsym(handle, sym);
	const char *e = dlerror();
	if (e) { *errmsg = strdup(e); return NULL; }
	return p;
}

static int call_get_cert(
	crdb_tls_get_cert_fn fn, const tls_conn_info_t *info,
	unsigned char **cert_out, int *cert_len,
	unsigned char **key_out,  int *key_len)
{
	return fn(info, cert_out, cert_len, key_out, key_len);
}

static int call_verify_cert(
	crdb_tls_verify_cert_fn fn, const tls_conn_info_t *info,
	const unsigned char * const *certs, const int *lens, int n)
{
	return fn(info, certs, lens, n);
}

static void call_free_buf(crdb_tls_free_buf_fn fn, void *ptr) { fn(ptr); }
*/
import "C"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cockroachdb/errors"
)

// TLSPlugin is a loaded instance of an external TLS plugin shared library.
// All exported methods are nil-safe: a nil *TLSPlugin is always a no-op.
type TLSPlugin struct {
	cfg     *TLSPluginConfig
	handle  unsafe.Pointer         // dlopen handle
	getCert C.crdb_tls_get_cert_fn
	verify  C.crdb_tls_verify_cert_fn
	freeBuf C.crdb_tls_free_buf_fn
}

// Load opens the shared library described by cfg and resolves all configured
// symbols. Returns (nil, nil) when cfg is nil (no plugin configured).
func Load(cfg *TLSPluginConfig) (*TLSPlugin, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &TLSPlugin{cfg: cfg}

	// dlopen the shared library.
	cpath := C.CString(cfg.SoPath)
	defer C.free(unsafe.Pointer(cpath))
	var cerr *C.char
	p.handle = C.crdb_dlopen(cpath, &cerr)
	if p.handle == nil {
		msg := C.GoString(cerr)
		C.free(unsafe.Pointer(cerr))
		return nil, errors.Newf("tlsplugin: dlopen(%q): %s", cfg.SoPath, msg)
	}

	// Resolve get-cert symbol.
	if cfg.Functions.GetCert != "" {
		sym, err := dlsym(p.handle, cfg.Functions.GetCert)
		if err != nil {
			return nil, errors.Wrapf(err, "tlsplugin: resolving get-cert symbol %q", cfg.Functions.GetCert)
		}
		p.getCert = C.crdb_tls_get_cert_fn(sym)

		// crdb_tls_free_buf is mandatory when get-cert is configured.
		freeSym, err := dlsym(p.handle, "crdb_tls_free_buf")
		if err != nil {
			return nil, errors.Newf(
				"tlsplugin: get-cert is configured but plugin does not export "+
					"\"crdb_tls_free_buf\": %s", err)
		}
		p.freeBuf = C.crdb_tls_free_buf_fn(freeSym)
	}

	// Resolve verify-cert symbol.
	if cfg.Functions.VerifyCert != "" {
		sym, err := dlsym(p.handle, cfg.Functions.VerifyCert)
		if err != nil {
			return nil, errors.Wrapf(err, "tlsplugin: resolving verify-cert symbol %q", cfg.Functions.VerifyCert)
		}
		p.verify = C.crdb_tls_verify_cert_fn(sym)
	}

	return p, nil
}

// dlsym wraps C.crdb_dlsym and returns the resolved pointer or an error.
func dlsym(handle unsafe.Pointer, name string) (unsafe.Pointer, error) {
	csym := C.CString(name)
	defer C.free(unsafe.Pointer(csym))
	var cerr *C.char
	ptr := C.crdb_dlsym(handle, csym, &cerr)
	if ptr == nil {
		msg := C.GoString(cerr)
		C.free(unsafe.Pointer(cerr))
		return nil, fmt.Errorf("%s", msg)
	}
	return ptr, nil
}

// InjectIntoTLSConfig wires the plugin hooks into tlsCfg.
// connType identifies the call site and is forwarded to every hook via
// tls_conn_info_t.conn_type.
// No-op when the receiver is nil or tlsCfg is nil.
//
// For configs that use GetConfigForClient (server-side), the hooks are
// injected into each per-connection inner config returned by the callback.
// The inner config's existing certificates (loaded from disk) serve as the
// fallback when a hook returns CRDB_TLS_FALLBACK.
func (p *TLSPlugin) InjectIntoTLSConfig(tlsCfg *tls.Config, connType ConnType) {
	if p == nil || tlsCfg == nil {
		return
	}

	cConnType := C.uint8_t(connType)

	// For server-side configs, GetConfigForClient returns a per-connection inner
	// config that holds the actual loaded certificates. Wrap the callback so the
	// plugin hooks are injected into each returned inner config, but only once
	// per unique config pointer (the cert manager caches configs between reloads).
	if tlsCfg.GetConfigForClient != nil {
		origGetConfig := tlsCfg.GetConfigForClient
		var (
			mu        sync.Mutex
			lastInner *tls.Config
		)
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			inner, err := origGetConfig(hello)
			if err != nil || inner == nil {
				return inner, err
			}
			mu.Lock()
			defer mu.Unlock()
			if inner != lastInner {
				// New inner config (first call or after certificate reload).
				// Inject plugin hooks once into this config.
				p.injectDirect(inner, cConnType)
				lastInner = inner
			}
			return inner, nil
		}
		// Return: hooks will be injected per-connection via the wrapped
		// GetConfigForClient. Do not set outer-config hooks; they are bypassed
		// by GetConfigForClient anyway.
		return
	}

	p.injectDirect(tlsCfg, cConnType)
}

// injectDirect injects plugin hooks directly into tlsCfg (which must not have
// GetConfigForClient set). The config's existing Certificates and CA pools
// serve as fallbacks when a hook returns CRDB_TLS_FALLBACK.
func (p *TLSPlugin) injectDirect(tlsCfg *tls.Config, cConnType C.uint8_t) {
	if p.getCert != nil {
		p.injectGetCertHooks(tlsCfg, cConnType)
	}
	if p.verify != nil {
		p.injectVerifyHook(tlsCfg, cConnType)
	}
}

// injectGetCertHooks wires the get-cert plugin hook into tlsCfg.
// Any Certificates already present in tlsCfg are saved as a fallback that is
// used when the hook returns CRDB_TLS_FALLBACK.
func (p *TLSPlugin) injectGetCertHooks(tlsCfg *tls.Config, cConnType C.uint8_t) {
	getCertFn := p.getCert
	freeBufFn := p.freeBuf

	// Capture and clear the disk-loaded certificates so that GetCertificate is
	// always called (making the plugin the primary cert source). Cleared certs
	// are used as the fallback when the hook returns CRDB_TLS_FALLBACK.
	fallbackCerts := tlsCfg.Certificates
	tlsCfg.Certificates = nil

	// Server-side: called when a remote client connects to us.
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		peerAddr := ""
		if hello.Conn != nil {
			peerAddr = hello.Conn.RemoteAddr().String()
		}
		info := makeCConnInfo(hello.ServerName, peerAddr, cConnType)
		defer freeCConnInfo(info)

		var certPtr *C.uchar
		var certLen C.int
		var keyPtr *C.uchar
		var keyLen C.int
		rc := C.call_get_cert(getCertFn, info, &certPtr, &certLen, &keyPtr, &keyLen)
		if rc == C.CRDB_TLS_FALLBACK {
			if len(fallbackCerts) == 0 {
				return nil, errors.New("tlsplugin: get-cert signaled fallback but no fallback certificate is configured")
			}
			return &fallbackCerts[0], nil
		}
		if rc != 0 {
			return nil, fmt.Errorf("tlsplugin: get-cert returned %d", int(rc))
		}
		cert, err := parseCertAndKey(certPtr, certLen, keyPtr, keyLen)
		C.call_free_buf(freeBufFn, unsafe.Pointer(certPtr))
		C.call_free_buf(freeBufFn, unsafe.Pointer(keyPtr))
		return cert, err
	}

	// Client-side: called when we initiate a connection to a peer.
	tlsCfg.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		info := makeCConnInfo("", "", cConnType)
		defer freeCConnInfo(info)

		var certPtr *C.uchar
		var certLen C.int
		var keyPtr *C.uchar
		var keyLen C.int
		rc := C.call_get_cert(getCertFn, info, &certPtr, &certLen, &keyPtr, &keyLen)
		if rc == C.CRDB_TLS_FALLBACK {
			if len(fallbackCerts) == 0 {
				return nil, errors.New("tlsplugin: get-cert (client) signaled fallback but no fallback certificate is configured")
			}
			return &fallbackCerts[0], nil
		}
		if rc != 0 {
			return nil, fmt.Errorf("tlsplugin: get-cert (client) returned %d", int(rc))
		}
		cert, err := parseCertAndKey(certPtr, certLen, keyPtr, keyLen)
		C.call_free_buf(freeBufFn, unsafe.Pointer(certPtr))
		C.call_free_buf(freeBufFn, unsafe.Pointer(keyPtr))
		return cert, err
	}
}

// injectVerifyHook wires the verify-cert plugin hook into tlsCfg.
//
// For server-side configs (ClientAuth >= VerifyClientCertIfGiven), the hook
// becomes the primary client-certificate verifier: ClientCAs is cleared and
// ClientAuth is downgraded to prevent Go's automatic chain validation from
// running before the plugin. The saved ClientCAs pool serves as the fallback
// when the hook returns CRDB_TLS_FALLBACK.
//
// For client-side configs, InsecureSkipVerify is set so that Go's standard
// server-certificate validation is bypassed. The saved RootCAs pool serves
// as the fallback.
func (p *TLSPlugin) injectVerifyHook(tlsCfg *tls.Config, cConnType C.uint8_t) {
	verifyFn := p.verify

	// Determine whether this is a server-side or client-side config and capture
	// the appropriate CA pool for fallback verification.
	var fallbackPool *x509.CertPool
	if tlsCfg.ClientCAs != nil || tlsCfg.ClientAuth >= tls.VerifyClientCertIfGiven {
		// Server-side inner config: plugin becomes the primary client-cert verifier.
		fallbackPool = tlsCfg.ClientCAs
		tlsCfg.ClientCAs = nil
		// Downgrade ClientAuth to prevent automatic chain verification while
		// still requesting (or requiring) a client certificate.
		switch tlsCfg.ClientAuth {
		case tls.VerifyClientCertIfGiven:
			tlsCfg.ClientAuth = tls.RequestClientCert
		case tls.RequireAndVerifyClientCert:
			tlsCfg.ClientAuth = tls.RequireAnyClientCert
		}
	} else {
		// Client-side config: plugin verifies the server certificate.
		fallbackPool = tlsCfg.RootCAs
		// Disable standard server-cert verification; the plugin (or fallback)
		// handles it entirely.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tlsplugin: peer sent no certificates")
		}
		n := len(rawCerts)
		ptrs := make([]*C.uchar, n)
		lens := make([]C.int, n)
		for i, der := range rawCerts {
			if len(der) == 0 {
				return fmt.Errorf("tlsplugin: cert[%d] is empty", i)
			}
			ptrs[i] = (*C.uchar)(unsafe.Pointer(&der[0]))
			lens[i] = C.int(len(der))
		}
		info := makeCConnInfo("", "", cConnType)
		defer freeCConnInfo(info)
		rc := C.call_verify_cert(verifyFn, info,
			(**C.uchar)(unsafe.Pointer(&ptrs[0])),
			(*C.int)(unsafe.Pointer(&lens[0])),
			C.int(n))
		if rc == C.CRDB_TLS_FALLBACK {
			if fallbackPool == nil {
				return errors.New("tlsplugin: verify-cert signaled fallback but no fallback CA is configured")
			}
			return verifyWithPool(rawCerts, fallbackPool)
		}
		if rc != 0 {
			return fmt.Errorf("tlsplugin: verify-cert rejected peer (rc=%d)", int(rc))
		}
		return nil
	}
}

// verifyWithPool performs standard x509 chain verification of rawCerts against
// pool. Used as the fallback when a verify-cert hook returns CRDB_TLS_FALLBACK.
func verifyWithPool(rawCerts [][]byte, pool *x509.CertPool) error {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.Wrapf(err, "tlsplugin: fallback: parsing cert[%d]", i)
		}
		certs[i] = cert
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		// Accept any extended key usage: verifyWithPool is called for both
		// client-side (verifying server auth) and server-side (verifying client
		// auth) fallback paths, so we cannot restrict to a single key usage here.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return errors.Wrap(err, "tlsplugin: fallback x509 verification failed")
	}
	return nil
}

// makeCConnInfo allocates a tls_conn_info_t on the C heap.
// Must be paired with freeCConnInfo.
func makeCConnInfo(serverName, peerAddr string, cConnType C.uint8_t) *C.tls_conn_info_t {
	info := (*C.tls_conn_info_t)(C.calloc(1, C.sizeof_tls_conn_info_t))
	info.peer_addr = C.CString(peerAddr)
	info.server_name = C.CString(serverName)
	info.conn_type = cConnType
	return info
}

// freeCConnInfo releases a tls_conn_info_t created by makeCConnInfo.
func freeCConnInfo(info *C.tls_conn_info_t) {
	C.free(unsafe.Pointer(info.peer_addr))
	C.free(unsafe.Pointer(info.server_name))
	C.free(unsafe.Pointer(info))
}

// peerAddr extracts "ip:port" from a net.Conn or returns "".
// Kept for future use when VerifyConnection is adopted.
func peerAddr(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

// parseCertAndKey converts DER-encoded cert+key C buffers into a tls.Certificate.
func parseCertAndKey(certPtr *C.uchar, certLen C.int, keyPtr *C.uchar, keyLen C.int) (*tls.Certificate, error) {
	certDER := C.GoBytes(unsafe.Pointer(certPtr), certLen)
	keyDER := C.GoBytes(unsafe.Pointer(keyPtr), keyLen)
	cert, err := tls.X509KeyPair(certDER, keyDER)
	if err != nil {
		return nil, errors.Wrap(err, "tlsplugin: parsing cert+key from plugin")
	}
	return &cert, nil
}
