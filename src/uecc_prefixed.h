#pragma once

// micro-ecc symbols are prefixed with recsrmesh_ : ESP-IDF's BT stack
// (tinycrypt) already exports uECC_* symbols, so unprefixed copies would
// collide at link time in firmware builds.
#define uECC_secp160r1 recsrmesh_uECC_secp160r1
#define uECC_secp192r1 recsrmesh_uECC_secp192r1
#define uECC_secp224r1 recsrmesh_uECC_secp224r1
#define uECC_secp256r1 recsrmesh_uECC_secp256r1
#define uECC_secp256k1 recsrmesh_uECC_secp256k1
#define uECC_set_rng recsrmesh_uECC_set_rng
#define uECC_curve_private_key_size recsrmesh_uECC_curve_private_key_size
#define uECC_curve_public_key_size recsrmesh_uECC_curve_public_key_size
#define uECC_make_key recsrmesh_uECC_make_key
#define uECC_shared_secret recsrmesh_uECC_shared_secret
#define uECC_compress recsrmesh_uECC_compress
#define uECC_decompress recsrmesh_uECC_decompress
#define uECC_valid_public_key recsrmesh_uECC_valid_public_key
#define uECC_compute_public_key recsrmesh_uECC_compute_public_key
#define uECC_sign recsrmesh_uECC_sign
#define uECC_sign_deterministic recsrmesh_uECC_sign_deterministic
#define uECC_verify recsrmesh_uECC_verify

#include "../external/micro-ecc/uECC.h"
