#include "recsrmesh/masp.h"
#include "recsrmesh/crypto.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "crypto_backend.h"

extern "C" {
#include "../external/micro-ecc/uECC.h"
}

namespace csrmesh::masp {

// Internal ECDH state: micro-ecc secp192r1 (Mbed TLS 4 removed the curve).
// Private key 24 bytes, public key 48 bytes (X||Y, big-endian).
struct EcpCtx {
    uint8_t priv[ECDH_COORD_LEN];
    uint8_t pub[2 * ECDH_COORD_LEN];
};

static int uecc_rng(uint8_t *dest, unsigned size) {
    return csrmesh::crypto::backend::random_bytes(dest, size) == Error::Ok ? 1 : 0;
}

Error init(Context &ctx, const char *network_passphrase) {
    ctx = {};

    const char mcp_salt[] = "\x00MCP";
    auto err =
        crypto::derive_key(network_passphrase, mcp_salt, sizeof(mcp_salt) - 1, ctx.network_key);
    if (err != Error::Ok)
        return err;

    const char masp_salt[] = "\x00MASP";
    err = crypto::derive_key("", masp_salt, sizeof(masp_salt) - 1, ctx.masp_key);
    if (err != Error::Ok)
        return err;

    // Generate ECDH keypair (SECP192R1) with micro-ecc
    auto *ecp = static_cast<EcpCtx *>(std::calloc(1, sizeof(EcpCtx)));
    if (!ecp)
        return Error::Ecdh;

    uECC_set_rng(uecc_rng);
    const struct uECC_Curve_t *curve = uECC_secp192r1();
    if (!uECC_make_key(ecp->pub, ecp->priv, curve)) {
        std::free(ecp);
        return Error::Ecdh;
    }

    {
        // Public key is X||Y big-endian; reverse each coordinate for LE transmission
        std::memcpy(ctx.pub_x_le, ecp->pub, ECDH_COORD_LEN);
        crypto::reverse_bytes(ctx.pub_x_le, ECDH_COORD_LEN);
        std::memcpy(ctx.pub_y_le, ecp->pub + ECDH_COORD_LEN, ECDH_COORD_LEN);
        crypto::reverse_bytes(ctx.pub_y_le, ECDH_COORD_LEN);
    }

    if (crypto::backend::random_bytes(ctx.local_random, 8) != Error::Ok) {
        std::free(ecp);
        return Error::Ecdh;
    }

    ctx.ecdh_ctx = ecp;
    return Error::Ok;
}

void set_target(Context &ctx, uint32_t uuid_hash31) {
    ctx.uuid_hash31 = uuid_hash31;
    ctx.uuid_hash31_bytes[0] = static_cast<uint8_t>(uuid_hash31 & 0xFF);
    ctx.uuid_hash31_bytes[1] = static_cast<uint8_t>((uuid_hash31 >> 8) & 0xFF);
    ctx.uuid_hash31_bytes[2] = static_cast<uint8_t>((uuid_hash31 >> 16) & 0xFF);
    ctx.uuid_hash31_bytes[3] = static_cast<uint8_t>((uuid_hash31 >> 24) & 0xFF);
}

void cleanup(Context &ctx) {
    if (ctx.ecdh_ctx) {
        std::free(ctx.ecdh_ctx);
        ctx.ecdh_ctx = nullptr;
    }
}

size_t build_device_id_announce(const Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 18)
        return 0;
    uint8_t packet[18] = {};
    packet[0] = static_cast<uint8_t>(Opcode::DeviceIdAnnounce);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    std::memcpy(packet + 6, crypto::default_seq_id.data(), 8);

    crypto::xor_masp_packet(packet, out, 18);
    return 18;
}

size_t build_assoc_request(Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 15)
        return 0;
    uint8_t packet[15] = {};
    packet[0] = static_cast<uint8_t>(Opcode::AssocRequest);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    packet[5] = ctx.use_short_code ? 0x01 : 0x00;
    std::memcpy(packet + 6, crypto::default_seq_id.data(), 8);
    packet[14] = static_cast<uint8_t>(crypto::get_version_counter() & 0xFF);

    crypto::xor_masp_packet(packet, out, 15);
    return 15;
}

bool parse_assoc_response(Context &ctx, const uint8_t *wire_data, size_t len,
                          int &confirm_type_out) {
    if (len < 6) {
        confirm_type_out = -1;
        return false;
    }

    uint8_t decrypted[64];
    crypto::xor_masp_packet(wire_data, decrypted, len);

    if (decrypted[0] != static_cast<uint8_t>(Opcode::AssocResponse)) {
        confirm_type_out = -1;
        return false;
    }

    uint32_t resp_hash =
        static_cast<uint32_t>(decrypted[1]) | (static_cast<uint32_t>(decrypted[2]) << 8) |
        (static_cast<uint32_t>(decrypted[3]) << 16) | (static_cast<uint32_t>(decrypted[4]) << 24);
    if (resp_hash != ctx.uuid_hash31) {
        confirm_type_out = -1;
        return false;
    }

    uint8_t ct = decrypted[5];
    confirm_type_out = ct;

    if (ct == 3)
        return false;
    if (ct != 0 && ct != 1)
        return false;

    ctx.confirm_type = ct;
    return true;
}

size_t build_pubkey_packet(Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 15)
        return 0;

    uint8_t packet[15] = {};
    packet[0] = static_cast<uint8_t>(Opcode::PubkeyRequest);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    packet[5] = ctx.pubkey_chunk_index;

    // Combined: Y first, then X (both LE)
    uint8_t combined[48];
    std::memcpy(combined, ctx.pub_y_le, ECDH_COORD_LEN);
    std::memcpy(combined + ECDH_COORD_LEN, ctx.pub_x_le, ECDH_COORD_LEN);

    size_t start = static_cast<size_t>(ctx.pubkey_chunk_index) * 8;
    if (start + 8 > 48)
        start = 48 - 8;
    std::memcpy(packet + 6, combined + start, 8);

    crypto::xor_masp_packet(packet, out, 15);
    return 15;
}

bool parse_pubkey_response(Context &ctx, const uint8_t *wire_data, size_t len) {
    if (len < 14)
        return false;

    uint8_t decrypted[64];
    crypto::xor_masp_packet(wire_data, decrypted, len);

    if (decrypted[0] != static_cast<uint8_t>(Opcode::PubkeyResponse))
        return false;

    uint8_t chunk_index = decrypted[5];
    if (chunk_index != ctx.pubkey_rx_index)
        return false;

    const uint8_t *chunk_data = decrypted + 6;
    size_t offset = static_cast<size_t>(chunk_index) * 8;

    if (offset < ECDH_COORD_LEN) {
        std::memcpy(ctx.device_pub_y + offset, chunk_data, 8);
    } else {
        size_t x_offset = offset - ECDH_COORD_LEN;
        if (x_offset + 8 <= ECDH_COORD_LEN)
            std::memcpy(ctx.device_pub_x + x_offset, chunk_data, 8);
    }

    ctx.pubkey_rx_index++;
    return true;
}

Error compute_shared_secret(Context &ctx) {
    auto *ecp = static_cast<EcpCtx *>(ctx.ecdh_ctx);
    if (!ecp)
        return Error::Ecdh;

    // Device pubkey is stored as LE; reverse each coordinate to BE for micro-ecc
    uint8_t peer_pub[2 * ECDH_COORD_LEN];
    std::memcpy(peer_pub, ctx.device_pub_x, ECDH_COORD_LEN);
    crypto::reverse_bytes(peer_pub, ECDH_COORD_LEN);
    std::memcpy(peer_pub + ECDH_COORD_LEN, ctx.device_pub_y, ECDH_COORD_LEN);
    crypto::reverse_bytes(peer_pub + ECDH_COORD_LEN, ECDH_COORD_LEN);

    uECC_set_rng(uecc_rng);
    // micro-ecc returns the shared X coordinate big-endian; store LE as before
    if (!uECC_shared_secret(peer_pub, ecp->priv, ctx.shared_secret, uECC_secp192r1()))
        return Error::Ecdh;
    crypto::reverse_bytes(ctx.shared_secret, ECDH_COORD_LEN);
    ctx.has_shared_secret = true;
    return Error::Ok;
}

// Build confirmation HMAC data
static size_t build_confirm_data(const Context &ctx, bool is_local, uint8_t *out,
                                 size_t /*out_cap*/) {
    const uint8_t *pub_y = is_local ? ctx.pub_y_le : ctx.device_pub_y;
    const uint8_t *pub_x = is_local ? ctx.pub_x_le : ctx.device_pub_x;
    size_t pos = 0;

    if (ctx.use_short_code && ctx.confirm_type == 1) {
        std::memcpy(out + pos, pub_y, ECDH_COORD_LEN);
        pos += ECDH_COORD_LEN;
        std::memcpy(out + pos, pub_x, ECDH_COORD_LEN);
        pos += ECDH_COORD_LEN;
        uint32_t sc = ctx.short_code;
        out[pos++] = static_cast<uint8_t>(sc & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 8) & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 16) & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 24) & 0xFF);
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = 0;
    } else {
        std::memcpy(out + pos, crypto::default_seq_id.data(), 8);
        pos += 8;
        out[pos++] = ctx.confirm_type;
        out[pos++] = (ctx.short_code != 0) ? 0x01 : 0x00;
        std::memcpy(out + pos, pub_y, ECDH_COORD_LEN);
        pos += ECDH_COORD_LEN;
        std::memcpy(out + pos, pub_x, ECDH_COORD_LEN);
        pos += ECDH_COORD_LEN;
        uint32_t sc = ctx.short_code;
        out[pos++] = static_cast<uint8_t>(sc & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 8) & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 16) & 0xFF);
        out[pos++] = static_cast<uint8_t>((sc >> 24) & 0xFF);
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = 0;
    }

    return pos;
}

size_t build_confirm_request(Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 14)
        return 0;

    uint8_t confirm_data[128];
    size_t cd_len = build_confirm_data(ctx, true, confirm_data, sizeof(confirm_data));

    crypto::hmac_sha256_truncated({confirm_data, cd_len}, {ctx.local_random, 8}, ctx.local_confirm,
                                  8);

    uint8_t packet[14] = {};
    packet[0] = static_cast<uint8_t>(Opcode::ConfirmRequest);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    std::memcpy(packet + 5, ctx.local_confirm, 8);

    crypto::xor_masp_packet(packet, out, 14);
    return 14;
}

bool parse_confirm_response(Context &ctx, const uint8_t *wire_data, size_t len) {
    if (len < 13)
        return false;

    uint8_t decrypted[64];
    crypto::xor_masp_packet(wire_data, decrypted, len);

    if (decrypted[0] != static_cast<uint8_t>(Opcode::ConfirmResponse))
        return false;

    std::memcpy(ctx.device_confirm, decrypted + 5, 8);
    ctx.has_device_confirm = true;
    return true;
}

size_t build_random_request(const Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 14)
        return 0;

    uint8_t packet[14] = {};
    packet[0] = static_cast<uint8_t>(Opcode::RandomRequest);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    std::memcpy(packet + 5, ctx.local_random, 8);

    crypto::xor_masp_packet(packet, out, 14);
    return 14;
}

bool parse_random_response(Context &ctx, const uint8_t *wire_data, size_t len) {
    if (len < 13)
        return false;

    uint8_t decrypted[64];
    crypto::xor_masp_packet(wire_data, decrypted, len);

    if (decrypted[0] != static_cast<uint8_t>(Opcode::RandomResponse))
        return false;

    std::memcpy(ctx.device_random, decrypted + 5, 8);
    ctx.has_device_random = true;

    if (!ctx.has_device_confirm)
        return false;

    // Verify device's confirmation
    uint8_t verify_data[128];
    size_t vd_len = build_confirm_data(ctx, false, verify_data, sizeof(verify_data));

    uint8_t expected_confirm[8];
    crypto::hmac_sha256_truncated({verify_data, vd_len}, {ctx.device_random, 8}, expected_confirm,
                                  8);

    uint8_t diff = 0;
    for (size_t i = 0; i < 8; i++)
        diff |= ctx.device_confirm[i] ^ expected_confirm[i];

    return diff == 0;
}

size_t build_device_id_packet(Context &ctx, uint16_t device_id, uint8_t *out, size_t out_cap) {
    if (out_cap < 8 || !ctx.has_shared_secret)
        return 0;

    uint8_t id_bytes[2] = {
        static_cast<uint8_t>(device_id & 0xFF),
        static_cast<uint8_t>(device_id >> 8),
    };

    uint8_t encrypted_id[2];
    crypto::xor_encrypt({id_bytes, 2}, {ctx.shared_secret, ECDH_COORD_LEN}, "DeviceID",
                        encrypted_id);

    uint8_t packet[8] = {};
    packet[0] = static_cast<uint8_t>(Opcode::DeviceIdDist);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    packet[5] = encrypted_id[0];
    packet[6] = encrypted_id[1];

    crypto::xor_masp_packet(packet, out, 8);
    return 8;
}

bool parse_device_id_ack(const uint8_t *wire_data, size_t len) {
    if (len < 1)
        return false;
    uint8_t decrypted[1];
    crypto::xor_masp_packet(wire_data, decrypted, 1);
    return decrypted[0] == static_cast<uint8_t>(Opcode::DeviceIdAck);
}

size_t build_netkey_packet(Context &ctx, uint8_t *out, size_t out_cap) {
    if (out_cap < 15 || !ctx.has_shared_secret)
        return 0;

    uint8_t encrypted_key[KEY_LEN];
    crypto::xor_encrypt({ctx.network_key, KEY_LEN}, {ctx.shared_secret, ECDH_COORD_LEN},
                        "NetworkKey", encrypted_key);

    uint8_t packet[15] = {};
    packet[0] = static_cast<uint8_t>(Opcode::NetkeyDist);
    std::memcpy(packet + 1, ctx.uuid_hash31_bytes, 4);
    packet[5] = ctx.netkey_chunk_index;

    size_t start = static_cast<size_t>(ctx.netkey_chunk_index) * 8;
    if (start + 8 > KEY_LEN)
        start = KEY_LEN - 8;
    std::memcpy(packet + 6, encrypted_key + start, 8);

    crypto::xor_masp_packet(packet, out, 15);
    return 15;
}

bool parse_netkey_ack(const uint8_t *wire_data, size_t len, uint8_t expected_index) {
    if (len < 6)
        return false;

    uint8_t decrypted[6];
    crypto::xor_masp_packet(wire_data, decrypted, 6);

    if (decrypted[0] != static_cast<uint8_t>(Opcode::NetkeyAck))
        return false;

    return decrypted[5] == expected_index;
}

}  // namespace csrmesh::masp
