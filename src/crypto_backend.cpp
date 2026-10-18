#include "crypto_backend.h"

#include <cstring>

// PSA Crypto on Mbed TLS 4 (tf-psa-crypto), legacy API on Mbed TLS 2/3.
// Force with RECSRMESH_CRYPTO_PSA / RECSRMESH_CRYPTO_LEGACY.
#if !defined(RECSRMESH_CRYPTO_PSA) && !defined(RECSRMESH_CRYPTO_LEGACY)
#if __has_include(<tf-psa-crypto/build_info.h>)
#define RECSRMESH_CRYPTO_PSA 1
#else
#define RECSRMESH_CRYPTO_LEGACY 1
#endif
#endif

#if defined(RECSRMESH_CRYPTO_PSA)
#include <psa/crypto.h>
#else
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#endif

namespace csrmesh::crypto::backend {

#if defined(RECSRMESH_CRYPTO_PSA)

const char *name() {
    return "psa";
}

static bool psa_ready() {
    return psa_crypto_init() == PSA_SUCCESS;
}

Error sha256(ByteSpan a, ByteSpan b, uint8_t out[32]) {
    if (!psa_ready())
        return Error::Crypto;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t out_len = 0;
    if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS ||
        (!a.empty() && psa_hash_update(&op, a.data(), a.size()) != PSA_SUCCESS) ||
        (!b.empty() && psa_hash_update(&op, b.data(), b.size()) != PSA_SUCCESS) ||
        psa_hash_finish(&op, out, 32, &out_len) != PSA_SUCCESS || out_len != 32) {
        psa_hash_abort(&op);
        return Error::Crypto;
    }
    return Error::Ok;
}

Error aes128_ofb(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out,
                 size_t len) {
    if (len == 0)
        return Error::Ok;
    if (!psa_ready())
        return Error::Crypto;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_key_id_t kid = 0;
    if (psa_import_key(&attr, key, 16, &kid) != PSA_SUCCESS)
        return Error::Crypto;
    Error result = Error::Ok;
    uint8_t block[16];
    size_t used = 16;
    for (size_t i = 0; i < len; i++) {
        if (used == 16) {
            size_t block_len = 0;
            if (psa_cipher_encrypt(kid, PSA_ALG_ECB_NO_PADDING, iv, 16, block, sizeof(block),
                                   &block_len) != PSA_SUCCESS ||
                block_len != 16) {
                result = Error::Crypto;
                break;
            }
            std::memcpy(iv, block, 16);
            used = 0;
        }
        out[i] = in[i] ^ iv[used++];
    }
    psa_destroy_key(kid);
    return result;
}

Error random_bytes(uint8_t *out, size_t len) {
    if (!psa_ready())
        return Error::Crypto;
    return psa_generate_random(out, len) == PSA_SUCCESS ? Error::Ok : Error::Crypto;
}

#else  // RECSRMESH_CRYPTO_LEGACY

const char *name() {
    return "legacy";
}

Error sha256(ByteSpan a, ByteSpan b, uint8_t out[32]) {
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    Error result = Error::Crypto;
    if (mbedtls_sha256_starts(&sha, 0) == 0 &&
        (a.empty() || mbedtls_sha256_update(&sha, a.data(), a.size()) == 0) &&
        (b.empty() || mbedtls_sha256_update(&sha, b.data(), b.size()) == 0) &&
        mbedtls_sha256_finish(&sha, out) == 0)
        result = Error::Ok;
    mbedtls_sha256_free(&sha);
    return result;
}

Error aes128_ofb(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out,
                 size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
        mbedtls_aes_free(&aes);
        return Error::Crypto;
    }
    size_t iv_off = 0;
    Error result =
        mbedtls_aes_crypt_ofb(&aes, len, &iv_off, iv, in, out) == 0 ? Error::Ok : Error::Crypto;
    mbedtls_aes_free(&aes);
    return result;
}

Error random_bytes(uint8_t *out, size_t len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    static const char pers[] = "recsrmesh_rng";
    Error result = Error::Crypto;
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              reinterpret_cast<const uint8_t *>(pers), sizeof(pers) - 1) == 0 &&
        mbedtls_ctr_drbg_random(&ctr_drbg, out, len) == 0)
        result = Error::Ok;
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return result;
}

#endif

Error hmac_sha256(ByteSpan data, ByteSpan key, uint8_t out[32]) {
    uint8_t k[64] = {};
    if (key.size() > 64) {
        if (sha256(key, {}, k) != Error::Ok)
            return Error::Crypto;
    } else if (!key.empty()) {
        std::memcpy(k, key.data(), key.size());
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    uint8_t inner[32];
    // sha256 over (ipad || data): emulate two-span with explicit buffer for ipad+data
    {
        // backend sha256 takes two spans; chain manually via a temp for data hashing:
        // hash ipad first using the two-span form with data as second span.
        if (sha256(ByteSpan(ipad, 64), data, inner) != Error::Ok)
            return Error::Crypto;
    }
    return sha256(ByteSpan(opad, 64), ByteSpan(inner, 32), out);
}

}  // namespace csrmesh::crypto::backend
