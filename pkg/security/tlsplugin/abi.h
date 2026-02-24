/*
 * CockroachDB TLS plugin ABI
 * ==========================
 * A plugin shared library may export either or both of the two
 * configurable hook functions below.  Which symbols to call is declared
 * via CLI flags (--tls-plugin-get-cert, --tls-plugin-verify-cert);
 * the names are NOT fixed.
 *
 * If get-cert is configured the plugin MUST also export the fixed symbol
 * "crdb_tls_free_buf" (HOOK 3).  CockroachDB resolves it automatically at
 * load time; it does NOT appear in flags or config.
 *
 * All pointers passed INTO hooks are valid only for the duration of the call.
 * Buffers passed OUT (cert_out, key_out) must be allocated by the plugin
 * with its own allocator and will be released via crdb_tls_free_buf.
 *
 * Return value convention
 * -----------------------
 * Every hook returns an int that signals one of two actions:
 *
 *   0                  – "use as-is": the hook succeeded; use the result
 *                        (cert/key pair for get-cert; accept the peer for
 *                        verify-cert).
 *
 *   CRDB_TLS_FALLBACK  – "fallback": the hook could not produce a result;
 *                        CockroachDB falls back to the file-based
 *                        CA/certificate/key configured via --certs-dir (if
 *                        any).  If no fallback is configured the connection
 *                        is aborted.
 *
 *   any other non-zero – "use as-is": the hook explicitly failed; abort the
 *                        TLS handshake with an error.
 */
#ifndef COCKROACH_TLS_PLUGIN_ABI_H
#define COCKROACH_TLS_PLUGIN_ABI_H

#include <stdint.h>

/*
 * CRDB_TLS_FALLBACK
 * Returned by a hook to signal that CockroachDB should use the file-based
 * fallback (CA/certificate/key loaded from --certs-dir).  If no fallback is
 * configured the connection is aborted.
 */
#define CRDB_TLS_FALLBACK (-1)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * tls_conn_info_t – connection context passed to every hook.
 * Fields are NULL/0 when information is unavailable (e.g. peer_addr is ""
 * inside VerifyPeerCertificate because Go's crypto/tls does not expose
 * net.Conn at that point).
 */
typedef struct {
    /* "ip:port" of the remote peer, NUL-terminated. May be "". */
    const char *peer_addr;
    /* TLS SNI from the ClientHello, NUL-terminated. NULL if absent. */
    const char *server_name;
    /*
     * Negotiated TLS version after handshake: 0x0304=TLS1.3, 0x0303=TLS1.2,
     * 0=unknown. Only set in verify-cert; always 0 in get-cert.
     */
    uint16_t tls_version;
    /*
     * 1 = intra-cluster node-to-node RPC connection.
     * 0 = external SQL/HTTP client connection.
     */
    uint8_t is_inter_node;
    /* Opaque NUL-terminated connection ID for log correlation. */
    const char *conn_id;
} tls_conn_info_t;


/*
 * HOOK 1 – Certificate provisioning (flag: --tls-plugin-get-cert)
 * -----
 * Called when the local side must present a certificate.
 * Invoked for both server-side (GetCertificate) and client-side
 * (GetClientCertificate) TLS handshakes.
 *
 * On success allocate *cert_out and *key_out with your own allocator
 * (e.g. malloc); CockroachDB releases them via crdb_tls_free_buf.
 * Both are single DER-encoded items (X.509 certificate and private key).
 *
 * When this hook is configured the plugin MUST also export crdb_tls_free_buf.
 *
 * Returns 0 on success.  Returns CRDB_TLS_FALLBACK to use the file-based
 * fallback certificate.  Any other non-zero value aborts the handshake.
 */
typedef int (*crdb_tls_get_cert_fn)(
    const tls_conn_info_t *conn_info,
    unsigned char        **cert_out, int *cert_len,
    unsigned char        **key_out,  int *key_len
);


/*
 * HOOK 2 – Peer certificate verification (flag: --tls-plugin-verify-cert)
 * -----
 * Called after the peer sends its certificate chain.
 * Standard Go x509 chain validation is DISABLED when this hook is configured
 * (InsecureSkipVerify=true); the plugin is the sole trust authority.
 *
 * raw_certs[0] is the peer leaf cert (DER); subsequent entries are the chain.
 * cert_lens is a parallel array of byte lengths.
 * All cert buffers are owned by CockroachDB; do not free or retain them.
 *
 * Returns 0 if the peer is trusted.  Returns CRDB_TLS_FALLBACK to fall back
 * to standard x509 chain verification using the configured CA file.  Any
 * other non-zero value aborts the handshake.
 */
typedef int (*crdb_tls_verify_cert_fn)(
    const tls_conn_info_t        *conn_info,
    const unsigned char * const  *raw_certs,
    const int                    *cert_lens,
    int                           n_certs
);


/*
 * HOOK 3 – Buffer release  (symbol name FIXED: "crdb_tls_free_buf")
 * -----
 * Releases a buffer allocated by the plugin inside get-cert.
 * Must use the same allocator as get-cert.
 * Required (and auto-resolved) only when get-cert is configured.
 * Must tolerate ptr == NULL.
 */
typedef void (*crdb_tls_free_buf_fn)(void *ptr);


/* =========================================================================
 * Implementation-side prototype helpers
 * =========================================================================
 *
 * When writing a plugin shared library (.so), define your hook functions with
 * the signatures below and export them with the names you pass to the CLI
 * flags.  The three macros expand to the concrete C function declarations so
 * you can paste them directly into your .c / .h source.
 *
 * Example usage
 * -------------
 *   #include "abi.h"
 *
 *   // Implement Hook 1 – called on every TLS handshake that needs a cert.
 *   CRDB_TLS_GET_CERT_PROTO(my_get_cert) {
 *       // fill *cert_out / *cert_len / *key_out / *key_len with DER data
 *       // allocated by malloc(); CockroachDB will call crdb_tls_free_buf.
 *       return 0;                // 0 = success, use this cert
 *       // return CRDB_TLS_FALLBACK; // fall back to --certs-dir cert
 *   }
 *
 *   // Implement Hook 2 – called to verify the peer's certificate chain.
 *   CRDB_TLS_VERIFY_CERT_PROTO(my_verify_cert) {
 *       // inspect raw_certs[0..n_certs-1] (DER bytes, lengths in cert_lens)
 *       return 0;                // 0 = trusted
 *       // return CRDB_TLS_FALLBACK; // fall back to --certs-dir CA verification
 *   }
 *
 *   // Implement Hook 3 – MUST be exported as the fixed symbol name below.
 *   CRDB_TLS_FREE_BUF_PROTO {
 *       free(ptr);
 *   }
 *
 * CLI flags to activate:
 *   --tls-plugin-so /path/to/plugin.so
 *   --tls-plugin-get-cert    my_get_cert      # matches Hook 1 above
 *   --tls-plugin-verify-cert my_verify_cert   # matches Hook 2 above
 */

/*
 * CRDB_TLS_GET_CERT_PROTO(fn_name)
 *   Expands to the full prototype for a Hook 1 implementation.
 *   fn_name is the exported symbol name passed to --tls-plugin-get-cert.
 */
#define CRDB_TLS_GET_CERT_PROTO(fn_name)                        \
    int fn_name(                                                \
        const tls_conn_info_t *conn_info,                      \
        unsigned char        **cert_out, int *cert_len,        \
        unsigned char        **key_out,  int *key_len)

/*
 * CRDB_TLS_VERIFY_CERT_PROTO(fn_name)
 *   Expands to the full prototype for a Hook 2 implementation.
 *   fn_name is the exported symbol name passed to --tls-plugin-verify-cert.
 */
#define CRDB_TLS_VERIFY_CERT_PROTO(fn_name)                     \
    int fn_name(                                                \
        const tls_conn_info_t        *conn_info,               \
        const unsigned char * const  *raw_certs,               \
        const int                    *cert_lens,               \
        int                           n_certs)

/*
 * CRDB_TLS_FREE_BUF_PROTO
 *   Expands to the prototype for the mandatory Hook 3 implementation.
 *   The exported symbol name is FIXED as "crdb_tls_free_buf" – do not change
 *   it.  CockroachDB resolves it automatically when get-cert is configured.
 */
#define CRDB_TLS_FREE_BUF_PROTO \
    void crdb_tls_free_buf(void *ptr)

#ifdef __cplusplus
}
#endif

#endif /* COCKROACH_TLS_PLUGIN_ABI_H */
