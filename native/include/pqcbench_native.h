#ifndef PQCBENCH_NATIVE_H
#define PQCBENCH_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  #if defined(PQCBENCH_NATIVE_EXPORTS)
    #define PQCBENCH_API __declspec(dllexport)
  #else
    #define PQCBENCH_API __declspec(dllimport)
  #endif
#else
  #define PQCBENCH_API
#endif

typedef enum {
    PQCBENCH_OK = 0,
    PQCBENCH_ERR_UNSUPPORTED = 1,
    PQCBENCH_ERR_RUNTIME = 2,
    PQCBENCH_ERR_ALLOC = 3
} pqcbench_status;

typedef struct {
    uint8_t *data;
    size_t len;
} pqcbench_buffer;

#ifdef __cplusplus
extern "C" {
#endif

PQCBENCH_API void pqcbench_free(void *ptr);

PQCBENCH_API int pqcbench_kem_is_supported(const char *algorithm);
PQCBENCH_API pqcbench_status pqcbench_kem_keypair(const char *algorithm,
                                                  pqcbench_buffer *public_key,
                                                  pqcbench_buffer *secret_key);
PQCBENCH_API pqcbench_status pqcbench_kem_encapsulate(const char *algorithm,
                                                      const uint8_t *public_key,
                                                      size_t public_key_len,
                                                      pqcbench_buffer *ciphertext,
                                                      pqcbench_buffer *shared_secret);
PQCBENCH_API pqcbench_status pqcbench_kem_decapsulate(const char *algorithm,
                                                      const uint8_t *secret_key,
                                                      size_t secret_key_len,
                                                      const uint8_t *ciphertext,
                                                      size_t ciphertext_len,
                                                      pqcbench_buffer *shared_secret);

PQCBENCH_API int pqcbench_sig_is_supported(const char *algorithm);
PQCBENCH_API pqcbench_status pqcbench_sig_keypair(const char *algorithm,
                                                  pqcbench_buffer *public_key,
                                                  pqcbench_buffer *secret_key);
PQCBENCH_API pqcbench_status pqcbench_sig_sign(const char *algorithm,
                                               const uint8_t *secret_key,
                                               size_t secret_key_len,
                                               const uint8_t *message,
                                               size_t message_len,
                                               pqcbench_buffer *signature);
PQCBENCH_API pqcbench_status pqcbench_sig_verify(const char *algorithm,
                                                 const uint8_t *public_key,
                                                 size_t public_key_len,
                                                 const uint8_t *message,
                                                 size_t message_len,
                                                 const uint8_t *signature,
                                                 size_t signature_len,
                                                 int *result);

PQCBENCH_API int pqcbench_has_rsa(void);
PQCBENCH_API pqcbench_status pqcbench_rsa_keypair(int bits,
                                                  pqcbench_buffer *public_key,
                                                  pqcbench_buffer *secret_key);
PQCBENCH_API pqcbench_status pqcbench_rsa_encapsulate(const uint8_t *public_key_der,
                                                      size_t public_key_len,
                                                      size_t shared_secret_len,
                                                      pqcbench_buffer *ciphertext,
                                                      pqcbench_buffer *shared_secret);
PQCBENCH_API pqcbench_status pqcbench_rsa_decapsulate(const uint8_t *secret_key_der,
                                                      size_t secret_key_len,
                                                      const uint8_t *ciphertext,
                                                      size_t ciphertext_len,
                                                      pqcbench_buffer *shared_secret);
PQCBENCH_API pqcbench_status pqcbench_rsa_sign(const uint8_t *secret_key_der,
                                               size_t secret_key_len,
                                               const uint8_t *message,
                                               size_t message_len,
                                               pqcbench_buffer *signature);
PQCBENCH_API pqcbench_status pqcbench_rsa_verify(const uint8_t *public_key_der,
                                                 size_t public_key_len,
                                                 const uint8_t *message,
                                                 size_t message_len,
                                                 const uint8_t *signature,
                                                 size_t signature_len,
                                                 int *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCBENCH_NATIVE_H */
