// Falcon signature demo using liboqs
// Generates a keypair, signs a message, and verifies the signature.
// Build is expected to link against liboqs and include oqs/oqs.h

#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 2 == 0) printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static const char *pick_alg_from_arg(const char *arg) {
    if (arg == NULL) return OQS_SIG_alg_falcon_512; // default to 512 variant
    if (strcasecmp(arg, "falcon512") == 0 || strcasecmp(arg, "falcon-512") == 0) return OQS_SIG_alg_falcon_512;
    if (strcasecmp(arg, "falcon1024") == 0 || strcasecmp(arg, "falcon-1024") == 0) return OQS_SIG_alg_falcon_1024;
    return arg; // assume caller passed a valid OQS alg name
}

int main(int argc, char *argv[]) {
    const char *requested = argc > 1 ? argv[1] : NULL;
    const char *alg_name = pick_alg_from_arg(requested);

    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        fprintf(stderr, "Algorithm not enabled in this liboqs build: %s\n", alg_name);
        return EXIT_FAILURE;
    }

    printf("OQS Falcon demo (alg=%s)\n", alg_name);

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new failed\n");
        return EXIT_FAILURE;
    }

    printf("Public key bytes: %zu\n", sig->length_public_key);
    printf("Secret key bytes: %zu\n", sig->length_secret_key);
    printf("Signature bytes (max): %zu\n", sig->length_signature);

    // Allocate keys
    uint8_t *public_key = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *secret_key = (uint8_t *)malloc(sig->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "malloc failed for keys\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return EXIT_FAILURE;
    }

    // Key generation
    clock_t t0 = clock();
    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    clock_t t1 = clock();
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return EXIT_FAILURE;
    }
    double keygen_ms = 1000.0 * (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
    printf("Keygen: %.3f ms\n", keygen_ms);

    // Message to sign
    const char *msg_str = "The quick brown fox jumps over the lazy dog";
    const uint8_t *message = (const uint8_t *)msg_str;
    size_t message_len = strlen(msg_str);

    // Sign
    uint8_t *signature = (uint8_t *)malloc(sig->length_signature);
    size_t sig_len = 0;
    if (signature == NULL) {
        fprintf(stderr, "malloc failed for signature\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return EXIT_FAILURE;
    }

    t0 = clock();
    rc = OQS_SIG_sign(sig, signature, &sig_len, message, message_len, secret_key);
    t1 = clock();
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "sign failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        free(signature);
        return EXIT_FAILURE;
    }
    double sign_ms = 1000.0 * (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
    printf("Sign: %.3f ms, signature length: %zu bytes\n", sign_ms, sig_len);

    // Verify
    t0 = clock();
    rc = OQS_SIG_verify(sig, message, message_len, signature, sig_len, public_key);
    t1 = clock();
    double verify_ms = 1000.0 * (double)(t1 - t0) / (double)CLOCKS_PER_SEC;

    printf("Verify: %.3f ms -> %s\n", verify_ms, rc == OQS_SUCCESS ? "OK" : "FAIL");
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "verification failed unexpectedly\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        free(signature);
        return EXIT_FAILURE;
    }

    // Negative test: tamper the message
    uint8_t *tampered = (uint8_t *)malloc(message_len);
    if (tampered) {
        memcpy(tampered, message, message_len);
        tampered[0] ^= 0x01; // flip 1 bit
        rc = OQS_SIG_verify(sig, tampered, message_len, signature, sig_len, public_key);
        printf("Verify(tampered): %s (expected FAIL)\n", rc == OQS_SUCCESS ? "OK" : "FAIL");
        free(tampered);
    }

    // Optional: print first few bytes
    printf("Public key (first 32 bytes):\n");
    hexdump(public_key, sig->length_public_key < 32 ? sig->length_public_key : 32);
    printf("Signature (first 64 bytes):\n");
    hexdump(signature, sig_len < 64 ? sig_len : 64);

    // Cleanup
    OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);

    return EXIT_SUCCESS;
}

