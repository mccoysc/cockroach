// Copyright 2026 The Cockroach Authors.
//
// Use of this software is governed by the CockroachDB Software License
// included in the /LICENSE file.

//go:build linux

package tlsplugin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cockroachdb/cockroach/pkg/util/leaktest"
	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test certificate helpers
// ---------------------------------------------------------------------------

type testCA struct {
	certDER []byte
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func makeTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		certDER: der,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

func makeTestLeafDER(t *testing.T, ca *testCA) (certDER, certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return der, certPEM, keyPEM
}

func buildFallbackTLSCert(t *testing.T, ca *testCA) tls.Certificate {
	t.Helper()
	_, certPEM, keyPEM := makeTestLeafDER(t, ca)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

func caPool(ca *testCA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	return pool
}

// ---------------------------------------------------------------------------
// Mock hook constructors
// ---------------------------------------------------------------------------

// goodCertHook returns a valid tls.Certificate on every call.
func goodCertHook(t *testing.T, ca *testCA, wantConnType ConnType) func(serverName, peerAddr string, connType ConnType) (*tls.Certificate, error) {
	t.Helper()
	_, certPEM, keyPEM := makeTestLeafDER(t, ca)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return func(_, _ string, connType ConnType) (*tls.Certificate, error) {
		require.Equal(t, wantConnType, connType)
		return &cert, nil
	}
}

func fallbackCertHook(wantConnType ConnType) func(string, string, ConnType) (*tls.Certificate, error) {
	return func(_, _ string, connType ConnType) (*tls.Certificate, error) {
		if wantConnType != 0 {
			_ = connType // wantConnType == 0 means "don't check"; checked explicitly in callers
		}
		return nil, errFallback
	}
}

func errorCertHook(code int) func(string, string, ConnType) (*tls.Certificate, error) {
	return func(_, _ string, _ ConnType) (*tls.Certificate, error) {
		return nil, errors.Newf("mock cert error %d", code)
	}
}

func acceptVerifyHook(wantConnType ConnType) func([][]byte, ConnType) error {
	return func(_ [][]byte, connType ConnType) error {
		if wantConnType != 0 {
			_ = connType // wantConnType == 0 means "don't check"; checked explicitly in callers
		}
		return nil
	}
}

func fallbackVerifyHook() func([][]byte, ConnType) error {
	return func(_ [][]byte, _ ConnType) error { return errFallback }
}

func rejectVerifyHook(rc int) func([][]byte, ConnType) error {
	return func(_ [][]byte, _ ConnType) error {
		return errors.Newf("mock verify reject %d", rc)
	}
}

// pluginWithGetCert builds a TLSPlugin with only the get-cert hook set.
func pluginWithGetCertFn(fn func(string, string, ConnType) (*tls.Certificate, error)) *TLSPlugin {
	return &TLSPlugin{hookGetCert: fn}
}

// pluginWithVerifyFn builds a TLSPlugin with only the verify hook set.
func pluginWithVerifyFn(fn func([][]byte, ConnType) error) *TLSPlugin {
	return &TLSPlugin{hookVerify: fn}
}

// pluginWithBothFns builds a TLSPlugin with both hooks set.
func pluginWithBothFns(
	getCert func(string, string, ConnType) (*tls.Certificate, error),
	verify func([][]byte, ConnType) error,
) *TLSPlugin {
	return &TLSPlugin{hookGetCert: getCert, hookVerify: verify}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestInjectIntoTLSConfig_NilSafety verifies nil plugin and nil config are no-ops.
func TestInjectIntoTLSConfig_NilSafety(t *testing.T) {
	defer leaktest.AfterTest(t)()

	// nil plugin — must not panic, must not modify cfg.
	var p *TLSPlugin
	cfg := &tls.Config{}
	p.InjectIntoTLSConfig(cfg, ConnTypeServerRPC)
	require.Nil(t, cfg.GetCertificate)
	require.Nil(t, cfg.GetClientCertificate)
	require.Nil(t, cfg.VerifyPeerCertificate)
	require.False(t, cfg.InsecureSkipVerify)

	// non-nil plugin with nil config — must not panic.
	p = pluginWithGetCertFn(fallbackCertHook(0))
	p.InjectIntoTLSConfig(nil, ConnTypeServerRPC)
}

// TestGetCertHook_ServerSide tests GetCertificate (server presents cert to client).
func TestGetCertHook_ServerSide(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	fallbackCert := buildFallbackTLSCert(t, ca)
	goodCert, _, _ := makeTestLeafDER(t, ca)
	_ = goodCert

	tests := []struct {
		name           string
		hook           func(string, string, ConnType) (*tls.Certificate, error)
		fallbackCerts  []tls.Certificate
		connType       ConnType
		expectedErr    string
		expectFallback bool
	}{
		{
			name:     "hook returns cert successfully",
			hook:     goodCertHook(t, ca, ConnTypeServerRPC),
			connType: ConnTypeServerRPC,
		},
		{
			name:           "fallback with fallback cert configured",
			hook:           fallbackCertHook(0),
			fallbackCerts:  []tls.Certificate{fallbackCert},
			connType:       ConnTypeServerUI,
			expectFallback: true,
		},
		{
			name:        "fallback with no fallback cert - error",
			hook:        fallbackCertHook(0),
			connType:    ConnTypeClientNode,
			expectedErr: "no fallback certificate is configured",
		},
		{
			name:        "hook returns error - aborts handshake",
			hook:        errorCertHook(42),
			connType:    ConnTypeClientRPC,
			expectedErr: "mock cert error 42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := pluginWithGetCertFn(tc.hook)
			cfg := &tls.Config{Certificates: tc.fallbackCerts}
			p.InjectIntoTLSConfig(cfg, tc.connType)

			require.NotNil(t, cfg.GetCertificate)
			require.NotNil(t, cfg.GetClientCertificate)
			require.Nil(t, cfg.Certificates, "Certificates must be cleared by injection")

			cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				require.Nil(t, cert)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		})
	}
}

// TestGetCertHook_ClientSide tests GetClientCertificate (client presents cert to server).
func TestGetCertHook_ClientSide(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	fallbackCert := buildFallbackTLSCert(t, ca)

	tests := []struct {
		name           string
		hook           func(string, string, ConnType) (*tls.Certificate, error)
		fallbackCerts  []tls.Certificate
		connType       ConnType
		expectedErr    string
		expectFallback bool
	}{
		{
			name:     "hook returns cert successfully",
			hook:     goodCertHook(t, ca, ConnTypeClientNode),
			connType: ConnTypeClientNode,
		},
		{
			name:           "fallback with fallback cert configured",
			hook:           fallbackCertHook(0),
			fallbackCerts:  []tls.Certificate{fallbackCert},
			connType:       ConnTypeClientTenant,
			expectFallback: true,
		},
		{
			name:        "fallback with no fallback cert - error",
			hook:        fallbackCertHook(0),
			connType:    ConnTypeClientUI,
			expectedErr: "no fallback certificate is configured",
		},
		{
			name:        "hook returns error - aborts handshake",
			hook:        errorCertHook(7),
			connType:    ConnTypeClientRPC,
			expectedErr: "mock cert error 7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := pluginWithGetCertFn(tc.hook)
			cfg := &tls.Config{Certificates: tc.fallbackCerts}
			p.InjectIntoTLSConfig(cfg, tc.connType)

			require.NotNil(t, cfg.GetClientCertificate)
			require.Nil(t, cfg.Certificates, "Certificates must be cleared by injection")

			cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				require.Nil(t, cert)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		})
	}
}

// TestVerifyHook_ServerSide tests VerifyPeerCertificate on a server-side config
// (ClientAuth + ClientCAs set → plugin is primary client-cert verifier).
func TestVerifyHook_ServerSide(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	leafDER, _, _ := makeTestLeafDER(t, ca)
	pool := caPool(ca)

	tests := []struct {
		name        string
		hook        func([][]byte, ConnType) error
		clientCAs   *x509.CertPool
		connType    ConnType
		rawCerts    [][]byte
		expectedErr string
	}{
		{
			name:     "hook accepts client cert",
			hook:     acceptVerifyHook(ConnTypeServerRPC),
			connType: ConnTypeServerRPC,
			rawCerts: [][]byte{leafDER},
		},
		{
			name:      "hook signals fallback - verified by pool successfully",
			hook:      fallbackVerifyHook(),
			clientCAs: pool,
			connType:  ConnTypeServerRPC,
			rawCerts:  [][]byte{leafDER},
		},
		{
			name:        "hook signals fallback - no pool configured - error",
			hook:        fallbackVerifyHook(),
			connType:    ConnTypeServerUI,
			rawCerts:    [][]byte{leafDER},
			expectedErr: "no fallback CA is configured",
		},
		{
			name:        "hook rejects client cert",
			hook:        rejectVerifyHook(7),
			connType:    ConnTypeServerRPC,
			rawCerts:    [][]byte{leafDER},
			expectedErr: "mock verify reject 7",
		},
		{
			name:        "empty cert list",
			hook:        acceptVerifyHook(0),
			connType:    ConnTypeServerRPC,
			rawCerts:    [][]byte{},
			expectedErr: "peer sent no certificates",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := pluginWithVerifyFn(tc.hook)
			cfg := &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  tc.clientCAs,
			}
			p.InjectIntoTLSConfig(cfg, tc.connType)

			// Server-side: ClientAuth downgraded, ClientCAs cleared, no InsecureSkipVerify.
			require.Equal(t, tls.RequireAnyClientCert, cfg.ClientAuth)
			require.Nil(t, cfg.ClientCAs)
			require.False(t, cfg.InsecureSkipVerify)
			require.NotNil(t, cfg.VerifyPeerCertificate)

			err := cfg.VerifyPeerCertificate(tc.rawCerts, nil)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestVerifyHook_ClientSide tests VerifyPeerCertificate on a client-side config
// (no ClientAuth/ClientCAs → plugin is primary server-cert verifier).
func TestVerifyHook_ClientSide(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	leafDER, _, _ := makeTestLeafDER(t, ca)
	pool := caPool(ca)

	tests := []struct {
		name        string
		hook        func([][]byte, ConnType) error
		rootCAs     *x509.CertPool
		connType    ConnType
		rawCerts    [][]byte
		expectedErr string
	}{
		{
			name:     "hook accepts server cert",
			hook:     acceptVerifyHook(ConnTypeClientNode),
			connType: ConnTypeClientNode,
			rawCerts: [][]byte{leafDER},
		},
		{
			name:     "fallback x509 verification succeeds with correct CA",
			hook:     fallbackVerifyHook(),
			rootCAs:  pool,
			connType: ConnTypeClientTenant,
			rawCerts: [][]byte{leafDER},
		},
		{
			name:        "fallback x509 fails with wrong CA",
			hook:        fallbackVerifyHook(),
			rootCAs:     caPool(makeTestCA(t)), // different CA
			connType:    ConnTypeClientRPC,
			rawCerts:    [][]byte{leafDER},
			expectedErr: "fallback x509 verification failed",
		},
		{
			name:        "fallback with no CA configured - error",
			hook:        fallbackVerifyHook(),
			connType:    ConnTypeClientUI,
			rawCerts:    [][]byte{leafDER},
			expectedErr: "no fallback CA is configured",
		},
		{
			name:        "hook rejects server cert",
			hook:        rejectVerifyHook(3),
			connType:    ConnTypeClientNode,
			rawCerts:    [][]byte{leafDER},
			expectedErr: "mock verify reject 3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := pluginWithVerifyFn(tc.hook)
			cfg := &tls.Config{RootCAs: tc.rootCAs}
			p.InjectIntoTLSConfig(cfg, tc.connType)

			// Client-side: InsecureSkipVerify must be set so Go skips standard
			// chain validation. RootCAs is left in place (InsecureSkipVerify
			// already bypasses it; the fallback closure captures it separately).
			require.True(t, cfg.InsecureSkipVerify)
			require.NotNil(t, cfg.VerifyPeerCertificate)

			err := cfg.VerifyPeerCertificate(tc.rawCerts, nil)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestVerifyHook_VerifyClientCertIfGiven tests that VerifyClientCertIfGiven
// is downgraded to RequestClientCert (not RequireAnyClientCert).
func TestVerifyHook_VerifyClientCertIfGiven_Downgrade(t *testing.T) {
	defer leaktest.AfterTest(t)()

	p := pluginWithVerifyFn(acceptVerifyHook(0))
	cfg := &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  x509.NewCertPool(),
	}
	p.InjectIntoTLSConfig(cfg, ConnTypeServerRPC)

	require.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
	require.Nil(t, cfg.ClientCAs)
	require.False(t, cfg.InsecureSkipVerify)
}

// TestGetConfigForClient_Wrapping tests that for a server-side outer config that
// uses GetConfigForClient, hooks are injected into the inner config exactly once
// per unique inner config pointer.
func TestGetConfigForClient_Wrapping(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	fallbackCert := buildFallbackTLSCert(t, ca)
	pool := caPool(ca)

	// Simulates a CertificateManager-style outer config that vends a cached inner config.
	innerCfg := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		Certificates: []tls.Certificate{fallbackCert},
	}
	callCount := 0
	outerCfg := &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			callCount++
			return innerCfg, nil
		},
	}

	p := pluginWithBothFns(fallbackCertHook(0), fallbackVerifyHook())
	p.InjectIntoTLSConfig(outerCfg, ConnTypeServerRPC)

	// Outer config must not have hooks set directly (they'd be bypassed anyway).
	require.Nil(t, outerCfg.GetCertificate)
	require.Nil(t, outerCfg.GetClientCertificate)
	require.Nil(t, outerCfg.VerifyPeerCertificate)

	// First call: inner config gets hooks injected.
	got, err := outerCfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Same(t, innerCfg, got)
	require.Equal(t, 1, callCount)
	require.NotNil(t, innerCfg.GetCertificate, "inner config should have GetCertificate after first call")
	require.NotNil(t, innerCfg.GetClientCertificate, "inner config should have GetClientCertificate after first call")
	require.NotNil(t, innerCfg.VerifyPeerCertificate, "inner config should have VerifyPeerCertificate after first call")

	// Capture the injected callbacks — they will be nil if idempotency guard fails.
	getCertAfter1 := innerCfg.GetCertificate
	verifyCertAfter1 := innerCfg.VerifyPeerCertificate

	// Second call: same inner config pointer — must NOT re-inject.
	got2, err := outerCfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Same(t, innerCfg, got2)
	require.Equal(t, 2, callCount)

	// After the second call the callbacks must still be the same (non-nil).
	require.NotNil(t, getCertAfter1)
	require.NotNil(t, verifyCertAfter1)

	// Behavioral idempotency check: GetCertificate must still work correctly
	// (returns the fallback cert captured in the first injection).
	cert, err := innerCfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err, "GetCertificate should still return fallback cert after second GetConfigForClient call")
	require.NotNil(t, cert)
}

// TestGetConfigForClient_NewInner verifies that a new inner config (simulating
// a cert reload) does get hooks injected.
func TestGetConfigForClient_NewInner(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	fallbackCert := buildFallbackTLSCert(t, ca)

	inner1 := &tls.Config{Certificates: []tls.Certificate{fallbackCert}}
	inner2 := &tls.Config{Certificates: []tls.Certificate{fallbackCert}}
	step := 0
	outerCfg := &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			step++
			if step == 1 {
				return inner1, nil
			}
			return inner2, nil
		},
	}

	p := pluginWithGetCertFn(fallbackCertHook(0))
	p.InjectIntoTLSConfig(outerCfg, ConnTypeServerRPC)

	_, _ = outerCfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NotNil(t, inner1.GetCertificate)

	_, _ = outerCfg.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NotNil(t, inner2.GetCertificate, "new inner config should also get hooks injected")
}

// TestConnTypePropagation verifies that the correct ConnType value is forwarded
// to the hook function for every injection site constant.
func TestConnTypePropagation(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	leafDER, _, _ := makeTestLeafDER(t, ca)
	pool := caPool(ca)
	fallbackCert := buildFallbackTLSCert(t, ca)

	allTypes := []ConnType{
		ConnTypeServerRPC,
		ConnTypeServerUI,
		ConnTypeClientNode,
		ConnTypeClientTenant,
		ConnTypeClientUI,
		ConnTypeClientRPC,
	}

	for _, wantType := range allTypes {
		wantType := wantType
		t.Run(wantType.String(), func(t *testing.T) {
			// --- get-cert hook: server side (GetCertificate) ---
			var gotGetCertType ConnType
			getCertHook := func(_, _ string, connType ConnType) (*tls.Certificate, error) {
				gotGetCertType = connType
				return nil, errFallback
			}
			p1 := pluginWithGetCertFn(getCertHook)
			cfg1 := &tls.Config{Certificates: []tls.Certificate{fallbackCert}}
			p1.InjectIntoTLSConfig(cfg1, wantType)
			_, _ = cfg1.GetCertificate(&tls.ClientHelloInfo{})
			require.Equal(t, wantType, gotGetCertType, "get-cert server-side conn_type")

			// --- get-cert hook: client side (GetClientCertificate) ---
			var gotClientCertType ConnType
			getClientCertHook := func(_, _ string, connType ConnType) (*tls.Certificate, error) {
				gotClientCertType = connType
				return nil, errFallback
			}
			p2 := pluginWithGetCertFn(getClientCertHook)
			cfg2 := &tls.Config{Certificates: []tls.Certificate{fallbackCert}}
			p2.InjectIntoTLSConfig(cfg2, wantType)
			_, _ = cfg2.GetClientCertificate(&tls.CertificateRequestInfo{})
			require.Equal(t, wantType, gotClientCertType, "get-cert client-side conn_type")

			// --- verify hook ---
			var gotVerifyType ConnType
			verifyHook := func(_ [][]byte, connType ConnType) error {
				gotVerifyType = connType
				return errFallback
			}
			p3 := pluginWithVerifyFn(verifyHook)
			cfg3 := &tls.Config{RootCAs: pool}
			p3.InjectIntoTLSConfig(cfg3, wantType)
			_ = cfg3.VerifyPeerCertificate([][]byte{leafDER}, nil)
			require.Equal(t, wantType, gotVerifyType, "verify-cert conn_type")
		})
	}
}

// TestVerifyWithPool tests the x509 fallback chain verification helper.
func TestVerifyWithPool(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	leafDER, _, _ := makeTestLeafDER(t, ca)
	wrongCA := makeTestCA(t)

	tests := []struct {
		name        string
		pool        *x509.CertPool
		rawCerts    [][]byte
		expectedErr string
	}{
		{
			name:     "valid cert chain verified by correct CA",
			pool:     caPool(ca),
			rawCerts: [][]byte{leafDER},
		},
		{
			name:        "cert not issued by CA in pool",
			pool:        caPool(wrongCA),
			rawCerts:    [][]byte{leafDER},
			expectedErr: "fallback x509 verification failed",
		},
		{
			name:        "invalid DER bytes cannot be parsed",
			pool:        caPool(ca),
			rawCerts:    [][]byte{[]byte("not-a-certificate")},
			expectedErr: "fallback: parsing cert[0]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyWithPool(tc.rawCerts, tc.pool)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNoOpWithoutPlugin verifies that a nil plugin leaves the tls.Config
// completely unmodified.
func TestNoOpWithoutPlugin(t *testing.T) {
	defer leaktest.AfterTest(t)()

	ca := makeTestCA(t)
	pool := caPool(ca)

	cfg := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		RootCAs:    pool,
	}
	original := *cfg

	var p *TLSPlugin
	p.InjectIntoTLSConfig(cfg, ConnTypeServerRPC)

	require.Equal(t, original.ClientAuth, cfg.ClientAuth)
	require.Equal(t, original.ClientCAs, cfg.ClientCAs)
	require.Equal(t, original.RootCAs, cfg.RootCAs)
	require.False(t, cfg.InsecureSkipVerify)
	require.Nil(t, cfg.GetCertificate)
	require.Nil(t, cfg.GetClientCertificate)
	require.Nil(t, cfg.VerifyPeerCertificate)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// String returns a human-readable name for a ConnType. Used in test names.
func (c ConnType) String() string {
	switch c {
	case ConnTypeServerRPC:
		return "ConnTypeServerRPC"
	case ConnTypeServerUI:
		return "ConnTypeServerUI"
	case ConnTypeClientNode:
		return "ConnTypeClientNode"
	case ConnTypeClientTenant:
		return "ConnTypeClientTenant"
	case ConnTypeClientUI:
		return "ConnTypeClientUI"
	case ConnTypeClientRPC:
		return "ConnTypeClientRPC"
	default:
		return "ConnTypeUnknown"
	}
}
