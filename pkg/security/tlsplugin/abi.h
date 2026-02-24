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
 * Return value convention: 0 = success/trusted, non-zero = error/rejected.
 */
#ifndef COCKROACH_TLS_PLUGIN_ABI_H
#define COCKROACH_TLS_PLUGIN_ABI_H

#include <stdint.h>

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
 * Returns 0 on success, non-zero to abort the handshake.
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
 * Returns 0 if the peer is trusted, non-zero to abort the handshake.
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

#ifdef __cplusplus
}
#endif

#endif /* COCKROACH_TLS_PLUGIN_ABI_H */
