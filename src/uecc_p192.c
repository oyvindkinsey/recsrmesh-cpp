// micro-ecc compiled for secp192r1 only, portable C implementation.
#define uECC_PLATFORM 0
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 1
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 0
#define uECC_SUPPORTS_secp256k1 0
#define uECC_SUPPORT_COMPRESSED_POINT 0
#include "../external/micro-ecc/uECC.c"
