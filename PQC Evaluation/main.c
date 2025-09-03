#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int aes256gcm_encrypt(const uint8_t *key32, const uint8_t *iv, size_t iv_len,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct, uint8_t tag[16]) {
    int ok = 0, len = 0, outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key32, iv) != 1) goto done;

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto done;
    outlen = len;

    if (EVP_EncryptFinal_ex(ctx, ct + outlen, &len) != 1) goto done; // GCM gives len=0
    outlen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
    ok = outlen; // return number of ciphertext bytes
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes256gcm_decrypt(const uint8_t *key32, const uint8_t *iv, size_t iv_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16],
                             uint8_t *pt_out) {
    int ok = 0, len = 0, outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key32, iv) != 1) goto done;

    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) goto done;
    outlen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt_out + outlen, &len) != 1) goto done;
    outlen += len;

    ok = outlen; // number of plaintext bytes
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv) {
    const char *PLAINTEXT = (argc > 1) ? argv[1] : "hello kyber hybrid";
    const size_t PT_LEN = strlen(PLAINTEXT);

    // 1) Receiver generates ML-KEM-768 keypair
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-768"); // NIST FIPS 203 (Kyber-768)
    if (!kem) { fprintf(stderr, "KEM not available\n"); return 1; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *kem_ct = malloc(kem->length_ciphertext);
    uint8_t *ss_sender = malloc(kem->length_shared_secret);
    uint8_t *ss_receiver = malloc(kem->length_shared_secret);

    if (!pk || !sk || !kem_ct || !ss_sender || !ss_receiver) { fprintf(stderr, "alloc\n"); return 2; }

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "keypair\n"); return 3; }

    // 2) Sender encapsulates to derive a shared secret
    if (OQS_KEM_encaps(kem, kem_ct, ss_sender, pk) != OQS_SUCCESS) { fprintf(stderr, "encaps\n"); return 4; }

    // For demo: use the 32-byte shared secret directly as AES-256 key
    // (In production, consider HKDF with context info.)
    uint8_t key[32];
    memcpy(key, ss_sender, 32);

    // 3) Symmetric encrypt plaintext with AES-256-GCM
    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof iv) != 1) { fprintf(stderr, "RAND_bytes\n"); return 5; }

    uint8_t *ct = malloc(PT_LEN);
    uint8_t tag[16];
    int ct_len = aes256gcm_encrypt(key, iv, sizeof iv,
                                   (const uint8_t *)PLAINTEXT, PT_LEN,
                                   ct, tag);
    if (ct_len <= 0) { fprintf(stderr, "encrypt fail\n"); return 6; }

    // Print artifacts you would transmit: (kem_ct, iv, tag, ct)
    print_hex("KEM ciphertext (to receiver)", kem_ct, kem->length_ciphertext);
    print_hex("AES-GCM IV", iv, sizeof iv);
    print_hex("AES-GCM tag", tag, sizeof tag);
    print_hex("AES-GCM ciphertext", ct, (size_t)ct_len);

    // 4) Receiver decapsulates -> derive same key, then decrypt
    if (OQS_KEM_decaps(kem, ss_receiver, kem_ct, sk) != OQS_SUCCESS) { fprintf(stderr, "decaps\n"); return 7; }
    if (memcmp(ss_sender, ss_receiver, kem->length_shared_secret) != 0) { fprintf(stderr, "ss mismatch\n"); return 8; }

    uint8_t *pt_out = malloc(ct_len);
    int pt_len = aes256gcm_decrypt(ss_receiver, iv, sizeof iv, ct, (size_t)ct_len, tag, pt_out);
    if (pt_len <= 0) { fprintf(stderr, "decrypt fail\n"); return 9; }

    printf("Recovered plaintext: %.*s\n", pt_len, (char *)pt_out);

    // Clean up
    OQS_KEM_free(kem);
    free(pk); free(sk); free(kem_ct); free(ss_sender); free(ss_receiver);
    free(ct); free(pt_out);
    return 0;
}
