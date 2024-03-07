#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {
    FILE *ca_cert_file = fopen("c1.pem", "r");
    if (!ca_cert_file) {
        fprintf(stderr, "Error: Unable to open CA certificate file.\n");
        return EXIT_FAILURE;
    }
    X509 *ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!ca_cert) {
        fprintf(stderr, "Error: Failed to read CA certificate.\n");
        return EXIT_FAILURE;
    }
    EVP_PKEY *ca_public_key = X509_get_pubkey(ca_cert);
    X509_free(ca_cert);
    if (!ca_public_key) {
        fprintf(stderr, "Error: Failed to extract public key from CA certificate.\n");
        return EXIT_FAILURE;
    }

    FILE *server_cert_file = fopen("c0.pem", "r");
    if (!server_cert_file) {
        fprintf(stderr, "Error: Unable to open server certificate file.\n");
        EVP_PKEY_free(ca_public_key);
        return EXIT_FAILURE;
    }
    X509 *server_cert = PEM_read_X509(server_cert_file, NULL, NULL, NULL);
    fclose(server_cert_file);
    if (!server_cert) {
        fprintf(stderr, "Error: Failed to read server certificate.\n");
        EVP_PKEY_free(ca_public_key);
        return EXIT_FAILURE;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Error: Failed to create message digest context.\n");
        X509_free(server_cert);
        EVP_PKEY_free(ca_public_key);
        return EXIT_FAILURE;
    }
    
    if (X509_verify(server_cert, ca_public_key) != 1) {
        fprintf(stderr, "Error: Signature verification failed.\n");
        EVP_PKEY_free(ca_public_key);
        X509_free(server_cert);
        EVP_MD_CTX_free(md_ctx);
        return EXIT_FAILURE;
    }
    
    printf("Signature verification succeeded.\n");

    X509_free(server_cert);
    EVP_PKEY_free(ca_public_key);
    EVP_MD_CTX_free(md_ctx);

    return EXIT_SUCCESS;
}