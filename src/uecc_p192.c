// micro-ecc compiled for secp192r1 only, portable C implementation,
// with recsrmesh_-prefixed symbols (see uecc_prefixed.h).
#define uECC_PLATFORM 0
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 1
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 0
#define uECC_SUPPORTS_secp256k1 0
#define uECC_SUPPORT_COMPRESSED_POINT 0
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
#define uECC_get_rng recsrmesh_uECC_get_rng
#define uECC_sign_with_k recsrmesh_uECC_sign_with_k
#include "../external/micro-ecc/uECC.c"
