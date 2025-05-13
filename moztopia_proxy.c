#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LISTEN_PORT 83
#define FORWARD_PORT 8000

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "./server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "./server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int forward_data(int client_sock) {
    int forward_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in forward_addr = {0};
    
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(FORWARD_PORT);
    forward_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(forward_sock, (struct sockaddr*)&forward_addr, sizeof(forward_addr)) < 0) {
        perror("Forward connection failed");
        close(forward_sock);
        return -1;
    }

    char buffer[4096];
    int bytes;

    while ((bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        printf("\n=== Incoming Request ===\n%s\n========================\n", buffer);
        send(forward_sock, buffer, bytes, 0);
        bytes = recv(forward_sock, buffer, sizeof(buffer) - 1, 0);
        buffer[bytes] = '\0';
        send(client_sock, buffer, bytes, 0);
    }

    close(forward_sock);
    return 0;
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {0};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LISTEN_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);

    printf("Listening on port %d...\n", LISTEN_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            forward_data(client_sock);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
