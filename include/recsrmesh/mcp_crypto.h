#pragma once

#include "types.h"

namespace csrmesh::mcp_crypto {

struct Decrypted {
    uint32_t seq;
    uint16_t source;
    uint8_t decrypted[64];
    size_t decrypted_len;
};

// SHA-256 key derivation: hash, reverse, truncate to 16 bytes
Error generate_key(ByteSpan input, uint8_t key_out[KEY_LEN]);

// Build encrypted MCP packet with HMAC. Returns total packet length.
size_t make_packet(const uint8_t *key, uint32_t seq, ByteSpan data,
                   uint8_t *out, size_t out_cap);

// Decrypt MCP packet and verify HMAC.
Error decrypt_packet(const uint8_t *key, ByteSpan data, Decrypted &result);

// Generate cryptographically random 24-bit sequence number (odd).
Error random_seq(uint32_t &seq_out);

}  // namespace csrmesh::mcp_crypto
