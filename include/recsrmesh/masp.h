#pragma once

#include "types.h"

#include <cstdint>

namespace csrmesh::masp {

enum class Opcode : uint8_t {
    DeviceIdAnnounce = 0x00,
    UuidAnnounce     = 0x01,
    AssocRequest     = 0x02,
    AssocResponse    = 0x03,
    PubkeyRequest    = 0x04,
    PubkeyResponse   = 0x05,
    ConfirmRequest   = 0x06,
    ConfirmResponse  = 0x07,
    RandomRequest    = 0x08,
    RandomResponse   = 0x09,
    DeviceIdDist     = 0x0A,
    DeviceIdAck      = 0x0B,
    NetkeyDist       = 0x0C,
    NetkeyAck        = 0x0D,
};

struct Context {
    // Our ECDH public key (little-endian, as transmitted)
    uint8_t pub_x_le[ECDH_COORD_LEN] = {};
    uint8_t pub_y_le[ECDH_COORD_LEN] = {};

    // Device's public key (filled during exchange)
    uint8_t device_pub_x[ECDH_COORD_LEN] = {};
    uint8_t device_pub_y[ECDH_COORD_LEN] = {};

    // Shared secret (computed after full key exchange)
    uint8_t shared_secret[ECDH_COORD_LEN] = {};
    bool has_shared_secret = false;

    // Network key (derived from passphrase + "\x00MCP")
    uint8_t network_key[KEY_LEN] = {};

    // MASP key (derived from "" + "\x00MASP")
    uint8_t masp_key[KEY_LEN] = {};

    // Target device
    uint32_t uuid_hash31 = 0;
    uint8_t uuid_hash31_bytes[4] = {};

    // Random nonces
    uint8_t local_random[8] = {};
    uint8_t device_random[8] = {};
    bool has_device_random = false;

    // Confirmation values
    uint8_t local_confirm[8] = {};
    uint8_t device_confirm[8] = {};
    bool has_device_confirm = false;

    // Confirm type from association response
    uint8_t confirm_type = 0;

    // Short code (optional)
    uint32_t short_code = 0;
    bool use_short_code = false;

    // Public key exchange chunk tracking
    uint8_t pubkey_chunk_index = 0;
    uint8_t pubkey_rx_index = 0;

    // Network key distribution chunk tracking
    uint8_t netkey_chunk_index = 0;

    // Opaque mbedtls ECDH context pointer
    void *ecdh_ctx = nullptr;
};

// Initialize: generate ECDH keypair, derive keys.
Error init(Context &ctx, const char *network_passphrase);

// Set target device for association
void set_target(Context &ctx, uint32_t uuid_hash31);

// Free ECDH context (mbedtls heap allocation)
void cleanup(Context &ctx);

// ---- Packet builders (return packet length, write to out) ----

size_t build_device_id_announce(const Context &ctx, uint8_t *out, size_t out_cap);
size_t build_assoc_request(Context &ctx, uint8_t *out, size_t out_cap);
size_t build_pubkey_packet(Context &ctx, uint8_t *out, size_t out_cap);
size_t build_confirm_request(Context &ctx, uint8_t *out, size_t out_cap);
size_t build_random_request(const Context &ctx, uint8_t *out, size_t out_cap);
size_t build_device_id_packet(Context &ctx, uint16_t device_id,
                              uint8_t *out, size_t out_cap);
size_t build_netkey_packet(Context &ctx, uint8_t *out, size_t out_cap);

// ---- Response parsers ----

bool parse_assoc_response(Context &ctx, const uint8_t *wire_data, size_t len,
                          int &confirm_type_out);
bool parse_pubkey_response(Context &ctx, const uint8_t *wire_data, size_t len);
Error compute_shared_secret(Context &ctx);
bool parse_confirm_response(Context &ctx, const uint8_t *wire_data, size_t len);
bool parse_random_response(Context &ctx, const uint8_t *wire_data, size_t len);
bool parse_device_id_ack(const uint8_t *wire_data, size_t len);
bool parse_netkey_ack(const uint8_t *wire_data, size_t len, uint8_t expected_index);

}  // namespace csrmesh::masp
