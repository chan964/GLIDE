/*
 * device_auth.c — ECQV+DID device authentication implementation.
 *
 * Measurement instrumentation:
 *   ENERGEST blocks mark the authentication window for energy measurement.
 *   RTIMER_NOW() calls mark latency measurement points.
 *   ROM/RAM footprint measured via msp430-size on the compiled binary.
 *
 * Crypto dependencies:
 *   - micro-ecc (uECC) for P-256 ECDSA sign/verify and ECDH
 *   - Contiki-NG native lib/sha256.h for SHA-256 (no mbedTLS needed)
 *   - Contiki-NG os/lib/cbor.h for CBOR encoding/decoding
 */

#include "device_auth.h"
#include "credentials.h"
#include "hkdf_sha256.h"

#include "contiki.h"
#include "sys/energest.h"
#include "sys/rtimer.h"
#include "os/lib/cbor.h"
#include "os/net/security/micro-ecc/uECC.h"
#include "sha256_impl.h"

#include <string.h>
#include <stdio.h>
#include "sys/log.h"
#define LOG_MODULE "DeviceAuth"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* ---------------------------------------------------------------------------
 * CBOR message type tags (must match Python cbor_codec.py)
 * --------------------------------------------------------------------------- */
#define PROTOCOL_VERSION    1
#define MSG_EDHOC_1         0x05
#define MSG_EDHOC_2         0x06

/* CBOR map keys (must match Python cbor_codec.py) */
#define KEY_VERSION         0
#define KEY_TYPE            1
#define KEY_CERT_INFO       3
#define KEY_R               4
#define KEY_SIGNATURE       7
#define KEY_EPHEMERAL       8
#define KEY_NONCE_D         9
#define KEY_NONCE_G         10

/* ---------------------------------------------------------------------------
 * SHA-256 using Contiki-NG native lib/sha256.h
 * --------------------------------------------------------------------------- */
static int sha256_hash(const uint8_t *data, size_t len, uint8_t *out)
{
    sha256_impl_hash(data, len, out);
    return 0;
}



/* ---------------------------------------------------------------------------
 * ECDSA signing using micro-ecc.
 * Hashes payload with SHA-256 first, then signs the 32-byte hash.
 * Produces 64-byte signature (r||s).
 * --------------------------------------------------------------------------- */
static int ecdsa_sign(
    const uint8_t *private_key,
    const uint8_t *payload,
    size_t         payload_len,
    uint8_t       *signature)
{
    uint8_t hash[32];
    uECC_Curve curve = uECC_secp256r1();

    sha256_hash(payload, payload_len, hash);

    if(!uECC_sign(private_key, hash, sizeof(hash), signature, curve)) {
        return AUTH_ERR_CRYPTO;
    }
    return AUTH_OK;
}

/* ---------------------------------------------------------------------------
 * ECDSA verification using micro-ecc.
 * public_key_uncompressed: 64 bytes (x||y), no 0x04 prefix.
 * --------------------------------------------------------------------------- */
static int ecdsa_verify(
    const uint8_t *public_key_uncompressed,
    const uint8_t *payload,
    size_t         payload_len,
    const uint8_t *signature)
{
    uint8_t hash[32];
    uECC_Curve curve = uECC_secp256r1();

    sha256_hash(payload, payload_len, hash);

    if(!uECC_verify(public_key_uncompressed, hash, sizeof(hash),
                    signature, curve)) {
        return AUTH_ERR_VERIFY;
    }
    return AUTH_OK;
}

/* ---------------------------------------------------------------------------
 * Decompress 33-byte compressed point to 64-byte uncompressed (x||y).
 * --------------------------------------------------------------------------- */
static void decompress_point(const uint8_t *compressed, uint8_t *uncompressed)
{
    uECC_Curve curve = uECC_secp256r1();
    uECC_decompress(compressed, uncompressed, curve);
}

/* ---------------------------------------------------------------------------
 * device_auth_build_msg1
 *
 * Builds EDHOC MSG_1 using pre-provisioned credentials from credentials.h.
 * Measures energy and latency via ENERGEST and RTIMER.
 * Returns number of bytes written on success, negative error code on failure.
 * --------------------------------------------------------------------------- */
int device_auth_build_msg1(device_auth_state_t *state,
                            uint8_t *buf, size_t buf_len)
{
    uECC_Curve curve = uECC_secp256r1();
    uint8_t E_d_uncompressed[64];
    uint8_t E_d_compressed[33];
    uint8_t signing_payload[33 + 33 + DEVICE_CERT_INFO_LEN + AUTH_NONCE_LEN];
    uint8_t signature[AUTH_SIGNATURE_LEN];
    cbor_writer_state_t cbor;
    rtimer_clock_t t_start, t_end;
    size_t sp_len = 0;
    size_t msg1_len;
    int ret;
    int i;

    t_start = RTIMER_NOW();
    ENERGEST_ON(ENERGEST_TYPE_CPU);

    /* Step 1: Generate ephemeral keypair */
    if(!uECC_make_key(E_d_uncompressed, state->e_d, curve)) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CRYPTO;
    }
    uECC_compress(E_d_uncompressed, E_d_compressed, curve);
    memcpy(state->E_d, E_d_uncompressed, 64);

    /* Step 2: Generate device nonce (fixed pattern for simulation) */
    for(i = 0; i < AUTH_NONCE_LEN; i++) {
        state->nonce_d[i] = (uint8_t)(i ^ 0xA5);
    }

    /* Step 3: Build signing payload = E_d || R || cert_info || nonce_d */
    memcpy(signing_payload + sp_len, E_d_compressed, 33);
    sp_len += 33;
    memcpy(signing_payload + sp_len, DEVICE_CERT_R, DEVICE_CERT_R_LEN);
    sp_len += DEVICE_CERT_R_LEN;
    memcpy(signing_payload + sp_len, DEVICE_CERT_INFO, DEVICE_CERT_INFO_LEN);
    sp_len += DEVICE_CERT_INFO_LEN;
    memcpy(signing_payload + sp_len, state->nonce_d, AUTH_NONCE_LEN);
    sp_len += AUTH_NONCE_LEN;

    /* Step 4: Sign with device long-term private key d */
    ret = ecdsa_sign(DEVICE_PRIVATE_KEY, signing_payload, sp_len, signature);
    if(ret != AUTH_OK) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return ret;
    }

    /* Step 5: CBOR-encode MSG_1 */
    cbor_init_writer(&cbor, buf, buf_len);
    cbor_open_map(&cbor);

    cbor_write_unsigned(&cbor, KEY_VERSION);
    cbor_write_unsigned(&cbor, PROTOCOL_VERSION);

    cbor_write_unsigned(&cbor, KEY_TYPE);
    cbor_write_unsigned(&cbor, MSG_EDHOC_1);

    cbor_write_unsigned(&cbor, KEY_CERT_INFO);
    cbor_write_data(&cbor, DEVICE_CERT_INFO, DEVICE_CERT_INFO_LEN);

    cbor_write_unsigned(&cbor, KEY_R);
    cbor_write_data(&cbor, DEVICE_CERT_R, DEVICE_CERT_R_LEN);

    cbor_write_unsigned(&cbor, KEY_SIGNATURE);
    cbor_write_data(&cbor, signature, AUTH_SIGNATURE_LEN);

    cbor_write_unsigned(&cbor, KEY_EPHEMERAL);
    cbor_write_data(&cbor, E_d_compressed, 33);

    cbor_write_unsigned(&cbor, KEY_NONCE_D);
    cbor_write_data(&cbor, state->nonce_d, AUTH_NONCE_LEN);

    cbor_close_map(&cbor);
    msg1_len = cbor_end_writer(&cbor);

    if(msg1_len == 0) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }
    if(msg1_len > AUTH_MSG1_MAX_LEN) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_BUFFER_SMALL;
    }

    /* Save MSG_1 bytes for transcript hash in MSG_2 processing */
    memcpy(state->msg1, buf, msg1_len);
    state->msg1_len = msg1_len;

    ENERGEST_OFF(ENERGEST_TYPE_CPU);
    t_end = RTIMER_NOW();

    LOG_INFO("[AUTH] MSG_1 built: %u bytes, %lu rtimer ticks\n",
           (unsigned)msg1_len,
           (unsigned long)(t_end - t_start));

    return (int)msg1_len;
}

/* ---------------------------------------------------------------------------
 * device_auth_process_msg2
 *
 * Parses EDHOC MSG_2, verifies gateway signature, performs ECDH,
 * derives 16-byte session key via HKDF-SHA256.
 * Returns AUTH_OK on success, negative error code on failure.
 * --------------------------------------------------------------------------- */
int device_auth_process_msg2(device_auth_state_t *state,
                              const uint8_t *msg2, size_t msg2_len,
                              uint8_t *session_key)
{
    uECC_Curve curve = uECC_secp256r1();
    cbor_reader_state_t reader;
    uint8_t E_g_compressed[33];
    uint8_t nonce_g[AUTH_NONCE_LEN];
    uint8_t sig_g[AUTH_SIGNATURE_LEN];
    uint8_t gw_pubkey_uncompressed[64];
    uint8_t E_g_uncompressed[64];
    uint8_t shared_secret[32];
    uint8_t verify_payload[AUTH_MSG1_MAX_LEN + 33 + AUTH_NONCE_LEN];
    uint8_t transcript[AUTH_MSG1_MAX_LEN + AUTH_MSG2_MAX_LEN];
    uint8_t salt[32];
    static const uint8_t HKDF_INFO[] = "edhoc-subset-v1-session-key";
    rtimer_clock_t t_start, t_end;
    size_t map_len;
    size_t verify_payload_len;
    size_t transcript_len;
    int got_E_g = 0, got_nonce_g = 0, got_sig = 0;
    int ret;
    size_t i;

    memset(E_g_compressed, 0, sizeof(E_g_compressed));
    memset(nonce_g, 0, sizeof(nonce_g));
    memset(sig_g, 0, sizeof(sig_g));

    ENERGEST_ON(ENERGEST_TYPE_CPU);
    t_start = RTIMER_NOW();

    /* Parse MSG_2 CBOR map */
    cbor_init_reader(&reader, msg2, msg2_len);
    map_len = cbor_read_map(&reader);
    if(map_len == SIZE_MAX) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }

    for(i = 0; i < map_len; i++) {
        uint64_t key = 0;
        cbor_read_unsigned(&reader, &key);

        if(key == KEY_EPHEMERAL) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == 33) {
                memcpy(E_g_compressed, d, 33);
                got_E_g = 1;
            }
        } else if(key == KEY_NONCE_G) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == AUTH_NONCE_LEN) {
                memcpy(nonce_g, d, AUTH_NONCE_LEN);
                got_nonce_g = 1;
            }
        } else if(key == KEY_SIGNATURE) {
            size_t dlen = 0;
            const uint8_t *d = cbor_read_data(&reader, &dlen);
            if(d && dlen == AUTH_SIGNATURE_LEN) {
                memcpy(sig_g, d, AUTH_SIGNATURE_LEN);
                got_sig = 1;
            }
        } else {
            /* Skip version and type fields */
            uint64_t dummy = 0;
            cbor_read_unsigned(&reader, &dummy);
        }
    }

    if(!got_E_g || !got_nonce_g || !got_sig) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CBOR;
    }

    /* Verify gateway signature over (MSG_1 || E_g || nonce_g) */
    decompress_point(GATEWAY_PUBLIC_KEY, gw_pubkey_uncompressed);

    verify_payload_len = state->msg1_len + 33 + AUTH_NONCE_LEN;
    memcpy(verify_payload, state->msg1, state->msg1_len);
    memcpy(verify_payload + state->msg1_len, E_g_compressed, 33);
    memcpy(verify_payload + state->msg1_len + 33, nonce_g, AUTH_NONCE_LEN);

    ret = ecdsa_verify(gw_pubkey_uncompressed,
                       verify_payload, verify_payload_len, sig_g);
    if(ret != AUTH_OK) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return ret;
    }

    /* ECDH: shared_secret = e_d * E_g */
    decompress_point(E_g_compressed, E_g_uncompressed);
    if(!uECC_shared_secret(E_g_uncompressed, state->e_d, shared_secret, curve)) {
        ENERGEST_OFF(ENERGEST_TYPE_CPU);
        return AUTH_ERR_CRYPTO;
    }

    /* HKDF: session_key = HKDF(SHA256(MSG1||MSG2), shared_secret) */
    transcript_len = state->msg1_len + msg2_len;
    memcpy(transcript, state->msg1, state->msg1_len);
    memcpy(transcript + state->msg1_len, msg2, msg2_len);
    sha256_hash(transcript, transcript_len, salt);

    ret = hkdf_sha256_derive(
        shared_secret, sizeof(shared_secret),
        salt,          sizeof(salt),
        HKDF_INFO,     sizeof(HKDF_INFO) - 1,
        session_key,   AUTH_SESSION_KEY_LEN
    );

    ENERGEST_OFF(ENERGEST_TYPE_CPU);
    t_end = RTIMER_NOW();

    if(ret != 0) {
        return AUTH_ERR_CRYPTO;
    }

    LOG_INFO("[AUTH] MSG_2 OK. Session key derived. %lu ticks\n",
           (unsigned long)(t_end - t_start));
    LOG_INFO("[AUTH] Key: ");
    for(i = 0; i < AUTH_SESSION_KEY_LEN; i++) {
        printf("%02x", session_key[i]);
    }
    printf("\n");

    return AUTH_OK;
}