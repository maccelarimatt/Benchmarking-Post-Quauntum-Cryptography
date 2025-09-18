#include "pqcbench_native.h"

#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#ifdef PQCBENCH_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#endif

static pqcbench_status alloc_buffer(pqcbench_buffer *buf, size_t len) {
    buf->data = NULL;
    buf->len = 0;
    if (len == 0) {
        return PQCBENCH_OK;
    }
    buf->data = (uint8_t *)malloc(len);
    if (!buf->data) {
        return PQCBENCH_ERR_ALLOC;
    }
    buf->len = len;
    return PQCBENCH_OK;
}

static void reset_buffer(pqcbench_buffer *buf) {
    if (!buf) {
        return;
    }
    buf->data = NULL;
    buf->len = 0;
}

static pqcbench_status kem_new(const char *algorithm, OQS_KEM **kem) {
    *kem = OQS_KEM_new(algorithm);
    if (!*kem) {
        return PQCBENCH_ERR_UNSUPPORTED;
    }
    return PQCBENCH_OK;
}

static pqcbench_status sig_new(const char *algorithm, OQS_SIG **sig) {
    *sig = OQS_SIG_new(algorithm);
    if (!*sig) {
        return PQCBENCH_ERR_UNSUPPORTED;
    }
    return PQCBENCH_OK;
}

#ifdef PQCBENCH_HAVE_OPENSSL
static pqcbench_status make_evp_from_public_der(const uint8_t *der, size_t len, EVP_PKEY **out) {
    const unsigned char *ptr = (const unsigned char *)der;
    *out = d2i_PUBKEY(NULL, &ptr, (long)len);
    if (!*out) {
        return PQCBENCH_ERR_RUNTIME;
    }
    return PQCBENCH_OK;
}

static pqcbench_status make_evp_from_private_der(const uint8_t *der, size_t len, EVP_PKEY **out) {
    const unsigned char *ptr = (const unsigned char *)der;
    *out = d2i_AutoPrivateKey(NULL, &ptr, (long)len);
    if (!*out) {
        return PQCBENCH_ERR_RUNTIME;
    }
    return PQCBENCH_OK;
}
#endif

void pqcbench_free(void *ptr) {
    free(ptr);
}

int pqcbench_kem_is_supported(const char *algorithm) {
    OQS_KEM *kem = OQS_KEM_new(algorithm);
    if (!kem) {
        return 0;
    }
    OQS_KEM_free(kem);
    return 1;
}

pqcbench_status pqcbench_kem_keypair(const char *algorithm,
                                     pqcbench_buffer *public_key,
                                     pqcbench_buffer *secret_key) {
    OQS_KEM *kem = NULL;
    pqcbench_status st = kem_new(algorithm, &kem);
    if (st != PQCBENCH_OK) {
        return st;
    }
    reset_buffer(public_key);
    reset_buffer(secret_key);
    st = alloc_buffer(public_key, kem->length_public_key);
    if (st != PQCBENCH_OK) {
        OQS_KEM_free(kem);
        return st;
    }
    st = alloc_buffer(secret_key, kem->length_secret_key);
    if (st != PQCBENCH_OK) {
        pqcbench_free(public_key->data);
        reset_buffer(public_key);
        OQS_KEM_free(kem);
        return st;
    }
    if (OQS_KEM_keypair(kem, public_key->data, secret_key->data) != OQS_SUCCESS) {
        pqcbench_free(public_key->data);
        pqcbench_free(secret_key->data);
        reset_buffer(public_key);
        reset_buffer(secret_key);
        OQS_KEM_free(kem);
        return PQCBENCH_ERR_RUNTIME;
    }
    OQS_KEM_free(kem);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_kem_encapsulate(const char *algorithm,
                                         const uint8_t *public_key,
                                         size_t public_key_len,
                                         pqcbench_buffer *ciphertext,
                                         pqcbench_buffer *shared_secret) {
    (void)public_key_len;
    OQS_KEM *kem = NULL;
    pqcbench_status st = kem_new(algorithm, &kem);
    if (st != PQCBENCH_OK) {
        return st;
    }
    reset_buffer(ciphertext);
    reset_buffer(shared_secret);
    st = alloc_buffer(ciphertext, kem->length_ciphertext);
    if (st != PQCBENCH_OK) {
        OQS_KEM_free(kem);
        return st;
    }
    st = alloc_buffer(shared_secret, kem->length_shared_secret);
    if (st != PQCBENCH_OK) {
        pqcbench_free(ciphertext->data);
        reset_buffer(ciphertext);
        OQS_KEM_free(kem);
        return st;
    }
    if (OQS_KEM_encaps(kem, ciphertext->data, shared_secret->data, public_key) != OQS_SUCCESS) {
        pqcbench_free(ciphertext->data);
        pqcbench_free(shared_secret->data);
        reset_buffer(ciphertext);
        reset_buffer(shared_secret);
        OQS_KEM_free(kem);
        return PQCBENCH_ERR_RUNTIME;
    }
    OQS_KEM_free(kem);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_kem_decapsulate(const char *algorithm,
                                         const uint8_t *secret_key,
                                         size_t secret_key_len,
                                         const uint8_t *ciphertext,
                                         size_t ciphertext_len,
                                         pqcbench_buffer *shared_secret) {
    (void)secret_key_len;
    (void)ciphertext_len;
    OQS_KEM *kem = NULL;
    pqcbench_status st = kem_new(algorithm, &kem);
    if (st != PQCBENCH_OK) {
        return st;
    }
    reset_buffer(shared_secret);
    st = alloc_buffer(shared_secret, kem->length_shared_secret);
    if (st != PQCBENCH_OK) {
        OQS_KEM_free(kem);
        return st;
    }
    if (OQS_KEM_decaps(kem, shared_secret->data, ciphertext, secret_key) != OQS_SUCCESS) {
        pqcbench_free(shared_secret->data);
        reset_buffer(shared_secret);
        OQS_KEM_free(kem);
        return PQCBENCH_ERR_RUNTIME;
    }
    OQS_KEM_free(kem);
    return PQCBENCH_OK;
}

int pqcbench_sig_is_supported(const char *algorithm) {
    OQS_SIG *sig = OQS_SIG_new(algorithm);
    if (!sig) {
        return 0;
    }
    OQS_SIG_free(sig);
    return 1;
}

pqcbench_status pqcbench_sig_keypair(const char *algorithm,
                                     pqcbench_buffer *public_key,
                                     pqcbench_buffer *secret_key) {
    OQS_SIG *sig = NULL;
    pqcbench_status st = sig_new(algorithm, &sig);
    if (st != PQCBENCH_OK) {
        return st;
    }
    reset_buffer(public_key);
    reset_buffer(secret_key);
    st = alloc_buffer(public_key, sig->length_public_key);
    if (st != PQCBENCH_OK) {
        OQS_SIG_free(sig);
        return st;
    }
    st = alloc_buffer(secret_key, sig->length_secret_key);
    if (st != PQCBENCH_OK) {
        pqcbench_free(public_key->data);
        reset_buffer(public_key);
        OQS_SIG_free(sig);
        return st;
    }
    if (OQS_SIG_keypair(sig, public_key->data, secret_key->data) != OQS_SUCCESS) {
        pqcbench_free(public_key->data);
        pqcbench_free(secret_key->data);
        reset_buffer(public_key);
        reset_buffer(secret_key);
        OQS_SIG_free(sig);
        return PQCBENCH_ERR_RUNTIME;
    }
    OQS_SIG_free(sig);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_sig_sign(const char *algorithm,
                                  const uint8_t *secret_key,
                                  size_t secret_key_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  pqcbench_buffer *signature) {
    (void)secret_key_len;
    OQS_SIG *sig = NULL;
    pqcbench_status st = sig_new(algorithm, &sig);
    if (st != PQCBENCH_OK) {
        return st;
    }
    reset_buffer(signature);
    st = alloc_buffer(signature, sig->length_signature);
    if (st != PQCBENCH_OK) {
        OQS_SIG_free(sig);
        return st;
    }
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature->data, &sig_len, message, message_len, secret_key) != OQS_SUCCESS) {
        pqcbench_free(signature->data);
        reset_buffer(signature);
        OQS_SIG_free(sig);
        return PQCBENCH_ERR_RUNTIME;
    }
    signature->len = sig_len;
    OQS_SIG_free(sig);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_sig_verify(const char *algorithm,
                                    const uint8_t *public_key,
                                    size_t public_key_len,
                                    const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *signature,
                                    size_t signature_len,
                                    int *result) {
    (void)public_key_len;
    OQS_SIG *sig = NULL;
    pqcbench_status st = sig_new(algorithm, &sig);
    if (st != PQCBENCH_OK) {
        return st;
    }
    OQS_STATUS ok = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    OQS_SIG_free(sig);
    if (ok == OQS_SUCCESS) {
        if (result) {
            *result = 1;
        }
        return PQCBENCH_OK;
    }
    if (result) {
        *result = 0;
    }
    return PQCBENCH_ERR_RUNTIME;
}

int pqcbench_has_rsa(void) {
#ifdef PQCBENCH_HAVE_OPENSSL
    return 1;
#else
    return 0;
#endif
}

#ifdef PQCBENCH_HAVE_OPENSSL
static pqcbench_status setup_oaep(EVP_PKEY_CTX *ctx) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    return PQCBENCH_OK;
}

static pqcbench_status setup_pss(EVP_PKEY_CTX *ctx) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_AUTO) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        return PQCBENCH_ERR_RUNTIME;
    }
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_rsa_keypair(int bits,
                                     pqcbench_buffer *public_key,
                                     pqcbench_buffer *secret_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    pqcbench_status st = PQCBENCH_OK;

    if (!ctx) {
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }

    reset_buffer(public_key);
    reset_buffer(secret_key);

    int pub_len = i2d_PUBKEY(pkey, NULL);
    int priv_len = i2d_PrivateKey(pkey, NULL);
    if (pub_len <= 0 || priv_len <= 0) {
        st = PQCBENCH_ERR_RUNTIME;
        goto cleanup;
    }

    st = alloc_buffer(public_key, (size_t)pub_len);
    if (st != PQCBENCH_OK) {
        goto cleanup;
    }
    st = alloc_buffer(secret_key, (size_t)priv_len);
    if (st != PQCBENCH_OK) {
        pqcbench_free(public_key->data);
        reset_buffer(public_key);
        goto cleanup;
    }

    unsigned char *pub_ptr = public_key->data;
    unsigned char *priv_ptr = secret_key->data;
    if (i2d_PUBKEY(pkey, &pub_ptr) <= 0 || i2d_PrivateKey(pkey, &priv_ptr) <= 0) {
        pqcbench_free(public_key->data);
        pqcbench_free(secret_key->data);
        reset_buffer(public_key);
        reset_buffer(secret_key);
        st = PQCBENCH_ERR_RUNTIME;
        goto cleanup;
    }

cleanup:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    EVP_PKEY_CTX_free(ctx);
    return st;
}

pqcbench_status pqcbench_rsa_encapsulate(const uint8_t *public_key_der,
                                         size_t public_key_len,
                                         size_t shared_secret_len,
                                         pqcbench_buffer *ciphertext,
                                         pqcbench_buffer *shared_secret) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    pqcbench_status st = make_evp_from_public_der(public_key_der, public_key_len, &pkey);
    if (st != PQCBENCH_OK) {
        return st;
    }
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    st = setup_oaep(ctx);
    if (st != PQCBENCH_OK) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return st;
    }

    reset_buffer(ciphertext);
    reset_buffer(shared_secret);

    st = alloc_buffer(shared_secret, shared_secret_len);
    if (st != PQCBENCH_OK) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return st;
    }
    if (RAND_bytes(shared_secret->data, (int)shared_secret_len) != 1) {
        pqcbench_free(shared_secret->data);
        reset_buffer(shared_secret);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }

    size_t ct_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &ct_len, shared_secret->data, shared_secret->len) <= 0) {
        pqcbench_free(shared_secret->data);
        reset_buffer(shared_secret);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    st = alloc_buffer(ciphertext, ct_len);
    if (st != PQCBENCH_OK) {
        pqcbench_free(shared_secret->data);
        reset_buffer(shared_secret);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return st;
    }
    if (EVP_PKEY_encrypt(ctx, ciphertext->data, &ct_len, shared_secret->data, shared_secret->len) <= 0) {
        pqcbench_free(ciphertext->data);
        pqcbench_free(shared_secret->data);
        reset_buffer(ciphertext);
        reset_buffer(shared_secret);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    ciphertext->len = ct_len;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_rsa_decapsulate(const uint8_t *secret_key_der,
                                         size_t secret_key_len,
                                         const uint8_t *ciphertext,
                                         size_t ciphertext_len,
                                         pqcbench_buffer *shared_secret) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    pqcbench_status st = make_evp_from_private_der(secret_key_der, secret_key_len, &pkey);
    if (st != PQCBENCH_OK) {
        return st;
    }
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    st = setup_oaep(ctx);
    if (st != PQCBENCH_OK) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return st;
    }
    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, ciphertext, ciphertext_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    reset_buffer(shared_secret);
    st = alloc_buffer(shared_secret, out_len);
    if (st != PQCBENCH_OK) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return st;
    }
    if (EVP_PKEY_decrypt(ctx, shared_secret->data, &out_len, ciphertext, ciphertext_len) <= 0) {
        pqcbench_free(shared_secret->data);
        reset_buffer(shared_secret);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return PQCBENCH_ERR_RUNTIME;
    }
    shared_secret->len = out_len;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_rsa_sign(const uint8_t *secret_key_der,
                                  size_t secret_key_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  pqcbench_buffer *signature) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    pqcbench_status st = make_evp_from_private_der(secret_key_der, secret_key_len, &pkey);
    if (st != PQCBENCH_OK) {
        return st;
    }
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    st = setup_pss(EVP_MD_CTX_pkey_ctx(mdctx));
    if (st != PQCBENCH_OK) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return st;
    }
    if (EVP_DigestSignUpdate(mdctx, message, message_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    reset_buffer(signature);
    st = alloc_buffer(signature, sig_len);
    if (st != PQCBENCH_OK) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return st;
    }
    if (EVP_DigestSignFinal(mdctx, signature->data, &sig_len) <= 0) {
        pqcbench_free(signature->data);
        reset_buffer(signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    signature->len = sig_len;
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return PQCBENCH_OK;
}

pqcbench_status pqcbench_rsa_verify(const uint8_t *public_key_der,
                                    size_t public_key_len,
                                    const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *signature,
                                    size_t signature_len,
                                    int *result) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    pqcbench_status st = make_evp_from_public_der(public_key_der, public_key_len, &pkey);
    if (st != PQCBENCH_OK) {
        return st;
    }
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    st = setup_pss(EVP_MD_CTX_pkey_ctx(mdctx));
    if (st != PQCBENCH_OK) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return st;
    }
    if (EVP_DigestVerifyUpdate(mdctx, message, message_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return PQCBENCH_ERR_RUNTIME;
    }
    int rc = EVP_DigestVerifyFinal(mdctx, signature, signature_len);
    if (result) {
        *result = (rc == 1) ? 1 : 0;
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    if (rc == 1) {
        return PQCBENCH_OK;
    }
    return PQCBENCH_ERR_RUNTIME;
}

#else /* PQCBENCH_HAVE_OPENSSL */

pqcbench_status pqcbench_rsa_keypair(int bits,
                                     pqcbench_buffer *public_key,
                                     pqcbench_buffer *secret_key) {
    (void)bits;
    (void)public_key;
    (void)secret_key;
    return PQCBENCH_ERR_UNSUPPORTED;
}

pqcbench_status pqcbench_rsa_encapsulate(const uint8_t *public_key_der,
                                         size_t public_key_len,
                                         size_t shared_secret_len,
                                         pqcbench_buffer *ciphertext,
                                         pqcbench_buffer *shared_secret) {
    (void)public_key_der;
    (void)public_key_len;
    (void)shared_secret_len;
    (void)ciphertext;
    (void)shared_secret;
    return PQCBENCH_ERR_UNSUPPORTED;
}

pqcbench_status pqcbench_rsa_decapsulate(const uint8_t *secret_key_der,
                                         size_t secret_key_len,
                                         const uint8_t *ciphertext,
                                         size_t ciphertext_len,
                                         pqcbench_buffer *shared_secret) {
    (void)secret_key_der;
    (void)secret_key_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)shared_secret;
    return PQCBENCH_ERR_UNSUPPORTED;
}

pqcbench_status pqcbench_rsa_sign(const uint8_t *secret_key_der,
                                  size_t secret_key_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  pqcbench_buffer *signature) {
    (void)secret_key_der;
    (void)secret_key_len;
    (void)message;
    (void)message_len;
    (void)signature;
    return PQCBENCH_ERR_UNSUPPORTED;
}

pqcbench_status pqcbench_rsa_verify(const uint8_t *public_key_der,
                                    size_t public_key_len,
                                    const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *signature,
                                    size_t signature_len,
                                    int *result) {
    (void)public_key_der;
    (void)public_key_len;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    if (result) {
        *result = 0;
    }
    return PQCBENCH_ERR_UNSUPPORTED;
}

#endif /* PQCBENCH_HAVE_OPENSSL */
