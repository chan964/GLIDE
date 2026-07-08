/*
 * device_auth.h — ECQV+DID device authentication for Contiki-NG.
 *
 * Implements the device side of the L-ECQV + DID-based EDHOC subset
 * authentication protocol described in the FYP.
 *
 * Uses:
 *   - micro-ecc (os/net/security/micro-ecc) for P-256 operations
 *   - Contiki-NG os/lib/cbor.h for CBOR encoding
 *   - hkdf_sha256.h for session key derivation
 *   - credentials.h for pre-provisioned device identity
 */

#ifndef DEVICE_AUTH_H_
#define DEVICE_AUTH_H_

#include <stdint.h>
#include <stddef.h>

/* Wire sizes matching Python cbor_codec.py */
#define AUTH_NONCE_LEN          16
#define AUTH_SIGNATURE_LEN      64
#define AUTH_COMPRESSED_PT_LEN  33
#define AUTH_SESSION_KEY_LEN    16

/* MSG_1 maximum size (conservative upper bound) */
#define AUTH_MSG1_MAX_LEN  256

/* MSG_2 maximum size */
#define AUTH_MSG2_MAX_LEN  192

/* Return codes */
#define AUTH_OK                  0
#define AUTH_ERR_CRYPTO         -1
#define AUTH_ERR_CBOR           -2
#define AUTH_ERR_VERIFY         -3
#define AUTH_ERR_BUFFER_SMALL   -4

/*
 * device_auth_state_t:
 *   State retained by the device between MSG_1 send and MSG_2 receive.
 *   Holds the ephemeral private key needed for session key derivation.
 *   Must NOT be transmitted.
 */
typedef struct {
    uint8_t e_d[32];           /* Ephemeral private key */
    uint8_t E_d[64];           /* Ephemeral public key (uncompressed x,y) */
    uint8_t nonce_d[16];       /* Device nonce */
    uint8_t msg1[AUTH_MSG1_MAX_LEN]; /* Saved MSG_1 bytes for transcript */
    size_t  msg1_len;
} device_auth_state_t;

/*
 * device_auth_build_msg1:
 *   Builds EDHOC MSG_1 using pre-provisioned credentials.
 *   Populates `state` which must be retained for MSG_2 processing.
 *
 *   buf/buf_len: output buffer for the CBOR-encoded MSG_1
 *   Returns number of bytes written, or negative on error.
 */
int device_auth_build_msg1(device_auth_state_t *state,
                            uint8_t *buf, size_t buf_len);

/*
 * device_auth_process_msg2:
 *   Verifies MSG_2 from gateway and derives the session key.
 *
 *   msg2/msg2_len: received CBOR-encoded MSG_2
 *   session_key:   output buffer for the 16-byte AES-128 session key
 *   Returns AUTH_OK on success, negative on error.
 */
int device_auth_process_msg2(device_auth_state_t *state,
                              const uint8_t *msg2, size_t msg2_len,
                              uint8_t *session_key);

#endif /* DEVICE_AUTH_H_ */