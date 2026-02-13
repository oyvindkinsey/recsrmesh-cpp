#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace csrmesh {

enum class Error {
    Ok = 0,
    InvalidArg,
    BufferTooSmall,
    Crypto,
    HmacMismatch,
    PacketTooShort,
    BleWrite,
    ProtoState,
    Ecdh,
    Busy,
};

enum class Characteristic {
    Low  = 0,  // 8003 - first fragment / short TX
    High = 1,  // 8004 - second fragment / short RX
};

inline constexpr size_t MTL_FRAG_SIZE       = 20;
inline constexpr size_t MTL_MAX_PACKET      = 40;
inline constexpr size_t MASP_XOR_MASK_LEN   = 25;
inline constexpr size_t KEY_LEN             = 16;
inline constexpr size_t ECDH_COORD_LEN      = 24;
inline constexpr size_t HMAC_LEN            = 32;
inline constexpr size_t PACKET_MAC_LEN      = 8;
inline constexpr size_t MTL_TIMEOUT_MS      = 200;
inline constexpr size_t MCP_CRYPTO_OVERHEAD = 14;
inline constexpr uint16_t MCP_CRYPTO_SOURCE = 0x8000;
inline constexpr uint8_t MCP_DISASSOCIATE_OPCODE = 0x04;
inline constexpr uint8_t MCP_MODEL_OPCODE        = 0x73;
inline constexpr size_t MCP_HEADER_LEN = 3;

using ByteSpan = std::span<const uint8_t>;

}  // namespace csrmesh
