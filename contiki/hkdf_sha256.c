#include "hkdf_sha256.h"
#include "sha256_impl.h"
#include <string.h>

static int hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *out)
{
    uint8_t k_ipad[64], k_opad[64], inner[32];
    sha256_impl_ctx_t ctx;
    size_t i;

    if(key_len > 64) { return -1; }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for(i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    sha256_impl_init(&ctx);
    sha256_impl_update(&ctx, k_ipad, 64);
    sha256_impl_update(&ctx, msg, msg_len);
    sha256_impl_final(&ctx, inner);

    sha256_impl_init(&ctx);
    sha256_impl_update(&ctx, k_opad, 64);
    sha256_impl_update(&ctx, inner, 32);
    sha256_impl_final(&ctx, out);
    return 0;
}

int hkdf_sha256_derive(
    const uint8_t *ikm,  size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm,        size_t okm_len)
{
    uint8_t prk[32], t[32], expand_input[129];
    size_t expand_len = 0;
    int ret;

    if(okm_len > 255*32) { return -1; }
    if(ikm_len != 32 || salt_len != 32) { return -1; }
    if(info_len > 128) { return -1; }

    ret = hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    if(ret) { return ret; }

    memcpy(expand_input, info, info_len);
    expand_len = info_len;
    expand_input[expand_len++] = 0x01;

    ret = hmac_sha256(prk, 32, expand_input, expand_len, t);
    if(ret) { return ret; }

    memcpy(okm, t, okm_len < 32 ? okm_len : 32);
    return 0;
}
