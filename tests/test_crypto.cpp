// Known-answer tests: expected values computed independently (Python
// hashlib/hmac, RFC 4231) - not captured from this implementation.
#include "recsrmesh/crypto.h"
#include "recsrmesh/mcp_crypto.h"

#include <cassert>
#include <cstdio>
#include <cstring>

using namespace csrmesh;

static void hex(const uint8_t *in, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * len] = 0;
}

int main() {
    // RFC 4231 test case 1: HMAC-SHA256, key = 20 x 0x0b, data = "Hi There"
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof(key));
        uint8_t out[32];
        char buf[65];
        assert(crypto::hmac_sha256(ByteSpan(reinterpret_cast<const uint8_t *>("Hi There"), 8),
                                   ByteSpan(key, sizeof(key)), out) == Error::Ok);
        hex(out, 32, buf);
        assert(strcmp(buf, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") ==
               0);
    }
    // derive_key("correct horse battery staple", "testsalt"): SHA256(pass+salt), reversed, first 16
    {
        uint8_t key[16];
        char buf[33];
        assert(crypto::derive_key("correct horse battery staple", "testsalt", 8, key) == Error::Ok);
        hex(key, 16, buf);
        assert(strcmp(buf, "5f70bd8a05cd00f1048c7c2a7bc1025f") == 0);
    }
    // mcp_crypto::generate_key("test input"): SHA256, reversed, first 16
    {
        uint8_t key[16];
        char buf[33];
        const char *in = "test input";
        assert(mcp_crypto::generate_key(ByteSpan(reinterpret_cast<const uint8_t *>(in), 10), key) ==
               Error::Ok);
        hex(key, 16, buf);
        assert(strcmp(buf, "aeae7a6cc6e1b24bf282458301db032a") == 0);
    }
    // UUID hashes for uuid = 00 01 02 ... 0f
    {
        uint8_t uuid[16];
        for (int i = 0; i < 16; i++)
            uuid[i] = static_cast<uint8_t>(i);
        assert(crypto::uuid_to_hash31(ByteSpan(uuid, 16)) == 0x6e3a8991u);
        assert(crypto::uuid_to_hash64(ByteSpan(uuid, 16)) == 0x202ffc38298b89dbULL);
    }
    // MCP packet round-trip and tamper detection
    {
        uint8_t key[16] = {0};
        const char *msg = "hello mesh";
        uint8_t packet[128];
        size_t len = mcp_crypto::make_packet(
            key, 42, ByteSpan(reinterpret_cast<const uint8_t *>(msg), 10), packet, sizeof(packet));
        assert(len > 10);
        mcp_crypto::Decrypted dec{};
        assert(mcp_crypto::decrypt_packet(key, ByteSpan(packet, len), dec) == Error::Ok);
        assert(dec.seq == 42);
        assert(dec.decrypted_len == 10);
        assert(memcmp(dec.decrypted, msg, 10) == 0);

        packet[2] ^= 0xFF;  // tamper with encrypted payload
        mcp_crypto::Decrypted bad{};
        assert(mcp_crypto::decrypt_packet(key, ByteSpan(packet, len), bad) != Error::Ok);
    }
    // Packet MAC: verify accepts own, rejects flipped payload byte
    {
        uint8_t key[16] = {1, 2, 3};
        const uint8_t payload[] = {0x10, 0x20, 0x30};
        uint8_t out[64];
        size_t out_len = 0;
        assert(crypto::add_packet_mac(ByteSpan(payload, 3), key, 5, out, &out_len) == Error::Ok);
        size_t payload_len = 0;
        bool valid = false;
        assert(crypto::verify_packet_mac(ByteSpan(out, out_len), key, &payload_len, &valid) ==
               Error::Ok);
        assert(valid && payload_len == 3);
        out[0] ^= 0xFF;
        assert(crypto::verify_packet_mac(ByteSpan(out, out_len), key, &payload_len, &valid) ==
               Error::Ok);
        assert(!valid);
    }
    printf("all crypto known-answer tests passed\n");
    return 0;
}
