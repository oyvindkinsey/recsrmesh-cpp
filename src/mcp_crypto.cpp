#include "recsrmesh/mcp_crypto.h"
#include "recsrmesh/crypto.h"

#include <cstring>

#include "crypto_backend.h"

namespace csrmesh::mcp_crypto {

Error generate_key(ByteSpan input, uint8_t key_out[KEY_LEN]) {
    uint8_t digest[32];
    if (crypto::backend::sha256(input, {}, digest) != Error::Ok)
        return Error::Crypto;

    crypto::reverse_bytes(digest, 32);
    std::memcpy(key_out, digest, KEY_LEN);
    return Error::Ok;
}

// AES-128-OFB encrypt/decrypt (same operation).
// IV: [seq(3), 0x00, source_lo, source_hi, 0x00*10]
static Error aes_ofb(const uint8_t *key, const uint8_t *seq_arr, uint16_t source, const uint8_t *in,
                     uint8_t *out, size_t len) {
    uint8_t iv[16] = {};
    iv[0] = seq_arr[0];
    iv[1] = seq_arr[1];
    iv[2] = seq_arr[2];
    iv[4] = static_cast<uint8_t>(source & 0xFF);
    iv[5] = static_cast<uint8_t>(source >> 8);

    return crypto::backend::aes128_ofb(key, iv, in, out, len);
}

size_t make_packet(const uint8_t *key, uint32_t seq, ByteSpan data, uint8_t *out, size_t out_cap) {
    size_t total = data.size() + MCP_CRYPTO_OVERHEAD;
    if (total > out_cap)
        return 0;

    uint16_t source = MCP_CRYPTO_SOURCE;
    uint8_t seq_arr[3] = {
        static_cast<uint8_t>(seq & 0xFF),
        static_cast<uint8_t>((seq >> 8) & 0xFF),
        static_cast<uint8_t>((seq >> 16) & 0xFF),
    };

    // Encrypt payload
    uint8_t encrypted[64];
    if (data.size() > sizeof(encrypted))
        return 0;
    if (aes_ofb(key, seq_arr, source, data.data(), encrypted, data.size()) != Error::Ok)
        return 0;

    // Build prehmac: 8 zero bytes + seq(3) + source(2) + encrypted payload
    uint8_t prehmac[128];
    size_t prehmac_len = 8 + 3 + 2 + data.size();
    if (prehmac_len > sizeof(prehmac))
        return 0;

    std::memset(prehmac, 0, 8);
    std::memcpy(prehmac + 8, seq_arr, 3);
    prehmac[11] = static_cast<uint8_t>(source & 0xFF);
    prehmac[12] = static_cast<uint8_t>(source >> 8);
    std::memcpy(prehmac + 13, encrypted, data.size());

    uint8_t hmac[PACKET_MAC_LEN];
    if (crypto::hmac_sha256_truncated({prehmac, prehmac_len}, {key, KEY_LEN}, hmac,
                                      PACKET_MAC_LEN) != Error::Ok)
        return 0;

    // Final packet: seq(3) + source(2) + encrypted(N) + hmac(8) + eof(1)
    size_t pos = 0;
    std::memcpy(out + pos, seq_arr, 3);
    pos += 3;
    out[pos++] = static_cast<uint8_t>(source & 0xFF);
    out[pos++] = static_cast<uint8_t>(source >> 8);
    std::memcpy(out + pos, encrypted, data.size());
    pos += data.size();
    std::memcpy(out + pos, hmac, PACKET_MAC_LEN);
    pos += PACKET_MAC_LEN;
    out[pos++] = 0xFF;

    return pos;
}

Error decrypt_packet(const uint8_t *key, ByteSpan data, Decrypted &result) {
    if (data.size() < MCP_CRYPTO_OVERHEAD)
        return Error::PacketTooShort;

    size_t payload_len = data.size() - MCP_CRYPTO_OVERHEAD;
    if (payload_len > sizeof(result.decrypted))
        return Error::BufferTooSmall;

    // Unpack: seq(3) + source(2) + encrypted(N) + hmac(8) + eof(1)
    uint8_t seq_arr[3];
    std::memcpy(seq_arr, data.data(), 3);
    uint16_t source = static_cast<uint16_t>(data[3]) | (static_cast<uint16_t>(data[4]) << 8);
    const uint8_t *encrypted = data.data() + 5;
    const uint8_t *hmac_received = data.data() + 5 + payload_len;

    // Verify HMAC: 8 zero bytes + seq(3) + source(2) + encrypted(N)
    uint8_t prehmac[128];
    size_t prehmac_len = 8 + 3 + 2 + payload_len;
    if (prehmac_len > sizeof(prehmac))
        return Error::BufferTooSmall;

    std::memset(prehmac, 0, 8);
    std::memcpy(prehmac + 8, seq_arr, 3);
    prehmac[11] = static_cast<uint8_t>(source & 0xFF);
    prehmac[12] = static_cast<uint8_t>(source >> 8);
    std::memcpy(prehmac + 13, encrypted, payload_len);

    uint8_t hmac_computed[PACKET_MAC_LEN];
    auto err = crypto::hmac_sha256_truncated({prehmac, prehmac_len}, {key, KEY_LEN}, hmac_computed,
                                             PACKET_MAC_LEN);
    if (err != Error::Ok)
        return err;

    // Constant-time HMAC compare
    uint8_t diff = 0;
    for (size_t i = 0; i < PACKET_MAC_LEN; i++)
        diff |= hmac_computed[i] ^ hmac_received[i];
    if (diff != 0)
        return Error::HmacMismatch;

    // Decrypt
    err = aes_ofb(key, seq_arr, source, encrypted, result.decrypted, payload_len);
    if (err != Error::Ok)
        return err;

    result.seq = static_cast<uint32_t>(seq_arr[0]) | (static_cast<uint32_t>(seq_arr[1]) << 8) |
                 (static_cast<uint32_t>(seq_arr[2]) << 16);
    result.source = source;
    result.decrypted_len = payload_len;
    return Error::Ok;
}

Error random_seq(uint32_t &seq_out) {
    uint8_t buf[3];
    if (crypto::backend::random_bytes(buf, sizeof(buf)) != Error::Ok)
        return Error::Crypto;
    seq_out = (static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
               (static_cast<uint32_t>(buf[2]) << 16)) |
              1;
    return Error::Ok;
}

}  // namespace csrmesh::mcp_crypto
