#ifndef ZEN_CRYPTO_TLS_H
#define ZEN_CRYPTO_TLS_H
/* OpenSSL ABI adapter. Handles session construction and native const types.
 * The caller keeps each fd open until after zen_tls_free and supplies stable
 * read/write storage across the Zen WANT_READ/WANT_WRITE retries. Single-threaded use
 * per session. These helpers implement no cryptographic primitives. */
#include <stdint.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
static void *zen_tls_client_context(void) { return SSL_CTX_new(TLS_client_method()); }
/* Const-qualified OpenSSL ABI cannot currently be expressed in Zen. */
static void *zen_tls_server_method(void) { return (void *)TLS_server_method(); }
static void zen_tls_selected(SSL *ssl, unsigned char **data, unsigned int *len) {
    const unsigned char *selected = NULL;
    SSL_get0_alpn_selected(ssl, &selected, len);
    *data = (unsigned char *)selected;
}
/* Typed native callback cast; protocol selection itself is Zen. */
static void zen_tls_set_alpn_callback(SSL_CTX *ctx, void *callback) {
    SSL_CTX_set_alpn_select_cb(ctx, (SSL_CTX_alpn_select_cb_func)callback, NULL);
}
static int zen_tls_has_h2(SSL *ssl) {
    const unsigned char *data = NULL; unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);
    return len == 2 && data[0] == 'h' && data[1] == '2';
}
static SSL *zen_tls_accept(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1) { SSL_free(ssl); return NULL; }
    SSL_set_accept_state(ssl);
    return ssl;
}
static void zen_tls_free(SSL *ssl) { SSL_free(ssl); }
#endif
