/*
 * sha256_impl.h — Minimal self-contained SHA-256 for Contiki-NG firmware.
 * No external dependencies. Works on any platform.
 */
#ifndef SHA256_IMPL_H_
#define SHA256_IMPL_H_
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} sha256_impl_ctx_t;

void sha256_impl_init(sha256_impl_ctx_t *ctx);
void sha256_impl_update(sha256_impl_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_impl_final(sha256_impl_ctx_t *ctx, uint8_t *digest);
void sha256_impl_hash(const uint8_t *data, size_t len, uint8_t *digest);

#endif /* SHA256_IMPL_H_ */
