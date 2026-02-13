#include "recsrmesh/crypto.h"

#include <algorithm>
#include <cstring>

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace csrmesh::crypto {

const std::array<uint8_t, MASP_XOR_MASK_LEN> masp_xor_mask = {
    0x52, 0x20, 0x2A, 0x39, 0x40, 0x18, 0xc4, 0x41,
    0xaa, 0xd1, 0x7d, 0x26, 0x05, 0xd5, 0x7f, 0xae,
    0x2c, 0xb3, 0x0e, 0xf5, 0xc5, 0x2d, 0x06, 0x24, 0x15,
};

const std::array<uint8_t, 8> default_seq_id = {1, 0, 0, 0, 0, 0, 0, 0};

static uint32_t version_counter = 0;

uint32_t get_version_counter()
{
    version_counter = (version_counter + 1) & 0xFFFFFF;
    return version_counter;
}

void set_version_counter(uint32_t value)
{
    version_counter = value & 0xFFFFFF;
}

void reverse_bytes(uint8_t *data, size_t len)
{
    std::reverse(data, data + len);
}

Error derive_key(const char *passphrase, const char *salt, size_t salt_len,
                 uint8_t key_out[KEY_LEN])
{
    mbedtls_sha256_context sha;
    uint8_t digest[32];

    mbedtls_sha256_init(&sha);
    if (mbedtls_sha256_starts(&sha, 0) != 0)
        goto err;
    if (passphrase && *passphrase) {
        if (mbedtls_sha256_update(&sha, reinterpret_cast<const uint8_t *>(passphrase),
                                  std::strlen(passphrase)) != 0)
            goto err;
    }
    if (salt_len > 0) {
        if (mbedtls_sha256_update(&sha, reinterpret_cast<const uint8_t *>(salt),
                                  salt_len) != 0)
            goto err;
    }
    if (mbedtls_sha256_finish(&sha, digest) != 0)
        goto err;
    mbedtls_sha256_free(&sha);

    reverse_bytes(digest, 32);
    std::memcpy(key_out, digest, KEY_LEN);
    return Error::Ok;

err:
    mbedtls_sha256_free(&sha);
    return Error::Crypto;
}

Error hmac_sha256(ByteSpan data, ByteSpan key, uint8_t out[HMAC_LEN])
{
    const auto *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return Error::Crypto;

    if (mbedtls_md_hmac(md_info, key.data(), key.size(),
                        data.data(), data.size(), out) != 0)
        return Error::Crypto;

    return Error::Ok;
}

Error hmac_sha256_truncated(ByteSpan data, ByteSpan key,
                            uint8_t *out, size_t out_len)
{
    uint8_t full[HMAC_LEN];
    auto err = hmac_sha256(data, key, full);
    if (err != Error::Ok)
        return err;

    const uint8_t *tail = full + (HMAC_LEN - out_len);
    for (size_t i = 0; i < out_len; i++)
        out[i] = tail[out_len - 1 - i];

    return Error::Ok;
}

void xor_bytes(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ b[i];
}

Error xor_encrypt(ByteSpan data, ByteSpan shared_secret,
                  const char *label, uint8_t *out)
{
    uint8_t keystream[64];
    size_t label_len = std::strlen(label);

    auto err = hmac_sha256_truncated(
        {reinterpret_cast<const uint8_t *>(label), label_len},
        shared_secret, keystream, data.size());
    if (err != Error::Ok)
        return err;

    xor_bytes(data.data(), keystream, out, data.size());
    return Error::Ok;
}

void xor_masp_packet(const uint8_t *in, uint8_t *out, size_t len)
{
    // Uses min(i, 24) NOT i%25 — intentional bug replication
    for (size_t i = 0; i < len; i++) {
        size_t mask_idx = std::min(i, MASP_XOR_MASK_LEN - 1);
        out[i] = in[i] ^ masp_xor_mask[mask_idx];
    }
}

Error add_packet_mac(ByteSpan payload, const uint8_t *key,
                     uint8_t ttl, uint8_t *out, size_t *out_len)
{
    size_t mac_input_len = 8 + payload.size();
    uint8_t mac_input[64];
    if (mac_input_len > sizeof(mac_input))
        return Error::BufferTooSmall;

    std::memset(mac_input, 0, 8);
    std::memcpy(mac_input + 8, payload.data(), payload.size());

    uint8_t mac[PACKET_MAC_LEN];
    auto err = hmac_sha256_truncated(
        {mac_input, mac_input_len},
        {key, KEY_LEN},
        mac, PACKET_MAC_LEN);
    if (err != Error::Ok)
        return err;

    std::memcpy(out, payload.data(), payload.size());
    std::memcpy(out + payload.size(), mac, PACKET_MAC_LEN);
    out[payload.size() + PACKET_MAC_LEN] = ttl;
    *out_len = payload.size() + PACKET_MAC_LEN + 1;
    return Error::Ok;
}

Error verify_packet_mac(ByteSpan packet, const uint8_t *key,
                        size_t *payload_len_out, bool *valid)
{
    *valid = false;
    if (packet.size() < 9) {
        *payload_len_out = packet.size();
        return Error::Ok;
    }

    size_t payload_len = packet.size() - 9;
    const uint8_t *received_mac = packet.data() + payload_len;

    size_t mac_input_len = 8 + payload_len;
    uint8_t mac_input[64];
    if (mac_input_len > sizeof(mac_input))
        return Error::BufferTooSmall;

    std::memset(mac_input, 0, 8);
    std::memcpy(mac_input + 8, packet.data(), payload_len);

    uint8_t expected_mac[PACKET_MAC_LEN];
    auto err = hmac_sha256_truncated(
        {mac_input, mac_input_len},
        {key, KEY_LEN},
        expected_mac, PACKET_MAC_LEN);
    if (err != Error::Ok)
        return err;

    *payload_len_out = payload_len;

    // Constant-time compare
    uint8_t diff = 0;
    for (size_t i = 0; i < PACKET_MAC_LEN; i++)
        diff |= received_mac[i] ^ expected_mac[i];
    *valid = (diff == 0);

    return Error::Ok;
}

uint32_t uuid_to_hash31(ByteSpan uuid_bytes)
{
    // Does NOT reverse UUID before hashing
    uint8_t digest[32];
    mbedtls_sha256(uuid_bytes.data(), uuid_bytes.size(), digest, 0);

    uint8_t last_4[4];
    std::memcpy(last_4, digest + 28, 4);
    last_4[0] &= 0x7F;  // mask MSB for 31 bits

    return (static_cast<uint32_t>(last_4[0]) << 24) |
           (static_cast<uint32_t>(last_4[1]) << 16) |
           (static_cast<uint32_t>(last_4[2]) << 8) |
            static_cast<uint32_t>(last_4[3]);
}

uint64_t uuid_to_hash64(ByteSpan uuid_bytes)
{
    uint8_t reversed[16];
    size_t len = std::min(uuid_bytes.size(), sizeof(reversed));
    std::memcpy(reversed, uuid_bytes.data(), len);
    reverse_bytes(reversed, len);

    uint8_t digest[32];
    mbedtls_sha256(reversed, len, digest, 0);

    uint64_t result = 0;
    for (size_t i = 0; i < 8; i++)
        result |= static_cast<uint64_t>(digest[24 + i]) << (i * 8);
    return result;
}

}  // namespace csrmesh::crypto
