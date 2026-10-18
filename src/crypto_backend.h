#pragma once

#include "recsrmesh/types.h"

namespace csrmesh::crypto::backend {

// SHA-256 over up to two concatenated spans (second may be empty)
Error sha256(ByteSpan a, ByteSpan b, uint8_t out[32]);

// HMAC-SHA-256 (RFC 2104) built on sha256 above
Error hmac_sha256(ByteSpan data, ByteSpan key, uint8_t out[32]);

// AES-128 OFB; iv is updated in place (carries keystream state)
Error aes128_ofb(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out,
                 size_t len);

Error random_bytes(uint8_t *out, size_t len);

const char *name();

}  // namespace csrmesh::crypto::backend
