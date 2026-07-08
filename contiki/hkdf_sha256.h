/*
 * hkdf_sha256.h — Minimal HKDF-SHA256 for Contiki-NG firmware.
 *
 * Implements RFC 5869 HKDF using Contiki-NG's mbedTLS SHA-256.
 * Used for session key derivation in the EDHOC subset handshake.
 *
 * Output length is fixed at 16 bytes (AES-128 session key).
 */

#ifndef HKDF_SHA256_H_
#define HKDF_SHA256_H_

#include <stdint.h>
#include <stddef.h>

#define HKDF_SHA256_HASH_LEN  32
#define HKDF_SESSION_KEY_LEN  16

/*
 * hkdf_sha256_derive:
 *   Derives a 16-byte session key from a shared secret and transcript.
 *
 *   salt     = SHA-256(msg1 || msg2)     [32 bytes]
 *   IKM      = ECDH shared secret        [32 bytes]
 *   info     = "edhoc-subset-v1-session-key"
 *   L        = 16 bytes
 *
 *   Returns 0 on success, nonzero on error.
 */
int hkdf_sha256_derive(
    const uint8_t *ikm,       /* Input keying material (ECDH shared secret) */
    size_t         ikm_len,   /* Must be 32 */
    const uint8_t *salt,      /* SHA-256(transcript) */
    size_t         salt_len,  /* Must be 32 */
    const uint8_t *info,      /* Context string */
    size_t         info_len,
    uint8_t       *okm,       /* Output: session key */
    size_t         okm_len    /* Must be <= 32 */
);

#endif /* HKDF_SHA256_H_ */
