/*
 * crdb_tls_plugin_example.c
 * =========================
 * Minimal skeleton for a CockroachDB TLS plugin shared library.
 *
 * Build (Linux, GCC):
 *   gcc -shared -fPIC -o my_tls_plugin.so crdb_tls_plugin_example.c
 *
 * Activate:
 *   cockroach start \
 *     --tls-plugin-so    /absolute/path/to/my_tls_plugin.so \
 *     --tls-plugin-get-cert    my_get_cert    \
 *     --tls-plugin-verify-cert my_verify_cert \
 *     ...
 *
 * This file is intentionally kept small.  Replace the stub bodies with real
 * logic (e.g. fetch a certificate from a hardware security module, verify a
 * peer against a custom PKI, etc.).
 *
 * See abi.h for the full ABI documentation.
 */

#include "abi.h"

#include <stdlib.h>   /* malloc / free */
#include <string.h>   /* memcpy */
#include <stdio.h>    /* fprintf (for diagnostics) */


/* -------------------------------------------------------------------------
 * HOOK 1 – Certificate provisioning
 *   Registered via --tls-plugin-get-cert my_get_cert
 * ------------------------------------------------------------------------- */
CRDB_TLS_GET_CERT_PROTO(my_get_cert)
{
    /*
     * Provide the local TLS certificate and private key in DER format.
     *
     * conn_info->is_inter_node == 1  => node-to-node RPC handshake
     * conn_info->is_inter_node == 0  => external client / HTTP handshake
     * conn_info->server_name         => TLS SNI (may be NULL)
     *
     * Allocate *cert_out and *key_out with malloc() (or any allocator whose
     * free function you export as crdb_tls_free_buf below).
     * CockroachDB calls crdb_tls_free_buf() on both buffers after use.
     *
     * Return values:
     *   0                  – success; cert/key are in *cert_out / *key_out
     *   CRDB_TLS_FALLBACK  – fall back to the --certs-dir certificate
     *   any other non-zero – abort the TLS handshake
     */

    /* TODO: replace with real certificate retrieval logic. */
    fprintf(stderr, "my_get_cert: stub called (peer=%s sni=%s inter_node=%d)\n",
            conn_info->peer_addr  ? conn_info->peer_addr  : "",
            conn_info->server_name ? conn_info->server_name : "",
            (int)conn_info->is_inter_node);

    *cert_out = NULL; *cert_len = 0;
    *key_out  = NULL; *key_len  = 0;
    return CRDB_TLS_FALLBACK; /* fall back to --certs-dir cert until implemented */
}


/* -------------------------------------------------------------------------
 * HOOK 2 – Peer certificate verification
 *   Registered via --tls-plugin-verify-cert my_verify_cert
 * -------------------------------------------------------------------------
 *
 * NOTE: When this hook is configured, CockroachDB makes the plugin the
 * primary trust authority.  Standard x509 chain validation is used only
 * if the hook returns CRDB_TLS_FALLBACK and a CA file is configured.
 */
CRDB_TLS_VERIFY_CERT_PROTO(my_verify_cert)
{
    /*
     * Inspect the peer's certificate chain.
     *
     * raw_certs[0]           = peer leaf certificate (DER-encoded)
     * raw_certs[1..n_certs-1]= intermediate / root certificates (DER)
     * cert_lens[i]           = byte length of raw_certs[i]
     *
     * conn_info->tls_version  = negotiated TLS version (e.g. 0x0304 = TLS 1.3)
     * conn_info->is_inter_node = 1 for node-to-node RPC connections
     *
     * Return values:
     *   0                  – accept the peer
     *   CRDB_TLS_FALLBACK  – fall back to standard x509 + --certs-dir CA
     *   any other non-zero – reject the peer
     */

    /* TODO: replace with real verification logic. */
    fprintf(stderr, "my_verify_cert: stub called (n_certs=%d peer=%s inter_node=%d)\n",
            n_certs,
            conn_info->peer_addr ? conn_info->peer_addr : "",
            (int)conn_info->is_inter_node);

    return CRDB_TLS_FALLBACK; /* fall back to CA file verification until implemented */
}


/* -------------------------------------------------------------------------
 * HOOK 3 – Buffer release  (symbol name is FIXED: "crdb_tls_free_buf")
 * -------------------------------------------------------------------------
 * CockroachDB calls this to release buffers allocated inside my_get_cert.
 * Must use the same allocator that was used to fill cert_out / key_out.
 * Must tolerate ptr == NULL.
 */
CRDB_TLS_FREE_BUF_PROTO
{
    free(ptr);
}
