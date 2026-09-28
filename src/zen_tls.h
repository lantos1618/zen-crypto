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
#ifdef __linux__
#include <errno.h>
#include <sys/socket.h>
/* Borrowed socket BIO: Linux lacks SO_NOSIGPIPE, so every TLS socket write
 * uses MSG_NOSIGNAL. No process-global signal disposition is changed. kTLS,
 * fast-open and descriptor ownership transfer are intentionally unsupported. */
struct zen_tls_socket { int fd, eof; };
static BIO_METHOD *zen_tls_socket_method;
static CRYPTO_ONCE zen_tls_socket_once = CRYPTO_ONCE_STATIC_INIT;
static int zen_tls_socket_create(BIO *bio) {
    struct zen_tls_socket *socket = OPENSSL_zalloc(sizeof(*socket));
    if (!socket) return 0;
    socket->fd = -1;
    BIO_set_data(bio, socket); BIO_set_init(bio, 0); BIO_set_shutdown(bio, BIO_NOCLOSE);
    return 1;
}
static int zen_tls_socket_destroy(BIO *bio) {
    if (!bio) return 0;
    OPENSSL_free(BIO_get_data(bio)); BIO_set_data(bio, NULL); BIO_set_init(bio, 0);
    return 1;
}
static int zen_tls_socket_write(BIO *bio, const char *bytes, int len) {
    struct zen_tls_socket *socket = BIO_get_data(bio);
    if (len <= 0) return 0;
    BIO_clear_retry_flags(bio); errno = 0;
    int n = (int)send(socket->fd, bytes, (size_t)len, MSG_NOSIGNAL);
    if (n <= 0 && BIO_sock_should_retry(n)) BIO_set_retry_write(bio);
    return n;
}
static int zen_tls_socket_read(BIO *bio, char *bytes, int len) {
    struct zen_tls_socket *socket = BIO_get_data(bio);
    if (len <= 0) return 0;
    BIO_clear_retry_flags(bio); errno = 0;
    int n = (int)recv(socket->fd, bytes, (size_t)len, 0);
    if (n == 0) socket->eof = 1;
    if (n <= 0 && BIO_sock_should_retry(n)) BIO_set_retry_read(bio);
    return n;
}
static long zen_tls_socket_ctrl(BIO *bio, int command, long value, void *pointer) {
    struct zen_tls_socket *socket = BIO_get_data(bio);
    (void)value;
    switch (command) {
    case BIO_C_SET_FD:
        if (!pointer) return 0;
        socket->fd = *(int *)pointer; socket->eof = 0; BIO_set_init(bio, 1); return 1;
    case BIO_C_GET_FD:
        if (!BIO_get_init(bio)) return -1;
        if (pointer) *(int *)pointer = socket->fd;
        return socket->fd;
    case BIO_CTRL_EOF: return socket->eof;
    case BIO_CTRL_FLUSH: return 1;
    case BIO_CTRL_GET_CLOSE: return BIO_NOCLOSE;
    default: return 0;
    }
}
static void zen_tls_socket_init(void) {
    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_SOCKET, "Zen borrowed socket MSG_NOSIGNAL");
    if (!method) return;
    if (!BIO_meth_set_create(method, zen_tls_socket_create)
        || !BIO_meth_set_destroy(method, zen_tls_socket_destroy)
        || !BIO_meth_set_read(method, zen_tls_socket_read)
        || !BIO_meth_set_write(method, zen_tls_socket_write)
        || !BIO_meth_set_ctrl(method, zen_tls_socket_ctrl)) { BIO_meth_free(method); return; }
    /* One immutable method retained for the process lifetime. */
    zen_tls_socket_method = method;
}
static int zen_tls_set_fd(SSL *ssl, int fd) {
    if (!CRYPTO_THREAD_run_once(&zen_tls_socket_once, zen_tls_socket_init)
        || !zen_tls_socket_method) return 0;
    BIO *bio = BIO_new(zen_tls_socket_method);
    if (!bio) return 0;
    if (BIO_set_fd(bio, fd, BIO_NOCLOSE) != 1) { BIO_free(bio); return 0; }
    SSL_set_bio(ssl, bio, bio);
    return 1;
}
#else
static int zen_tls_set_fd(SSL *ssl, int fd) { return SSL_set_fd(ssl, fd); }
#endif
static SSL *zen_tls_accept(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl || zen_tls_set_fd(ssl, fd) != 1) { SSL_free(ssl); return NULL; }
    SSL_set_accept_state(ssl);
    return ssl;
}
static void zen_tls_free(SSL *ssl) { SSL_free(ssl); }
#endif
