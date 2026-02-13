#pragma once

#include "types.h"

namespace csrmesh::mcp {

struct Parsed {
    uint16_t source;
    uint8_t opcode;
    const uint8_t *payload;
    size_t payload_len;
};

// Build MCP packet: [dest_lo, dest_hi, opcode, payload...]. Returns total length.
size_t build(uint16_t dest_id, uint8_t opcode, ByteSpan payload,
             uint8_t *out, size_t out_cap);

// Parse decrypted MCP packet. Returns false if < 3 bytes.
bool parse(ByteSpan data, Parsed &parsed);

// Build disassociate packet (opcode 0x04, 10 zero bytes). Returns total length.
size_t build_disassociate(uint16_t device_id, uint8_t *out, size_t out_cap);

}  // namespace csrmesh::mcp
