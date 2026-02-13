#pragma once

#include "types.h"

#include <array>

namespace csrmesh::crypto {

// MASP XOR mask (25 bytes)
extern const std::array<uint8_t, MASP_XOR_MASK_LEN> masp_xor_mask;

// Default sequence ID (8 bytes, little-endian 1)
extern const std::array<uint8_t, 8> default_seq_id;

// SHA256(passphrase + salt) -> reverse all 32 bytes -> take first 16
Error derive_key(const char *passphrase, const char *salt, size_t salt_len,
                 uint8_t key_out[KEY_LEN]);

// HMAC-SHA256(data, key) -> full 32-byte output
Error hmac_sha256(ByteSpan data, ByteSpan key, uint8_t out[HMAC_LEN]);

// HMAC-SHA256 truncated: last N bytes of HMAC, reversed
Error hmac_sha256_truncated(ByteSpan data, ByteSpan key,
                            uint8_t *out, size_t out_len);

// XOR two equal-length buffers
void xor_bytes(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len);

// XOR encryption using HMAC-derived keystream (for MASP shared-secret fields)
Error xor_encrypt(ByteSpan data, ByteSpan shared_secret,
                  const char *label, uint8_t *out);

// XOR MASP packet with fixed mask. Uses min(i, 24) NOT i%25.
void xor_masp_packet(const uint8_t *in, uint8_t *out, size_t len);

// Add 8-byte HMAC + TTL byte to packet. out must have room for in_len+9.
Error add_packet_mac(ByteSpan payload, const uint8_t *key,
                     uint8_t ttl, uint8_t *out, size_t *out_len);

// Verify and strip MAC. Returns payload length via payload_len_out.
Error verify_packet_mac(ByteSpan packet, const uint8_t *key,
                        size_t *payload_len_out, bool *valid);

// SHA256(uuid_bytes) -> mask MSB of last 4 bytes -> 31-bit hash
uint32_t uuid_to_hash31(ByteSpan uuid_bytes);

// SHA256(reverse(uuid_bytes)) -> last 8 bytes as LE uint64
uint64_t uuid_to_hash64(ByteSpan uuid_bytes);

// Reverse byte array in-place
void reverse_bytes(uint8_t *data, size_t len);

// Global version counter (24-bit, wrapping)
uint32_t get_version_counter();
void set_version_counter(uint32_t value);

}  // namespace csrmesh::crypto
