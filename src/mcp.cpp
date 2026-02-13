#include "recsrmesh/mcp.h"

#include <cstring>

namespace csrmesh::mcp {

size_t build(uint16_t dest_id, uint8_t opcode, ByteSpan payload,
             uint8_t *out, size_t out_cap)
{
    size_t total = MCP_HEADER_LEN + payload.size();
    if (total > out_cap)
        return 0;

    out[0] = static_cast<uint8_t>(dest_id & 0xFF);
    out[1] = static_cast<uint8_t>(dest_id >> 8);
    out[2] = opcode;
    if (!payload.empty())
        std::memcpy(out + MCP_HEADER_LEN, payload.data(), payload.size());

    return total;
}

bool parse(ByteSpan data, Parsed &parsed)
{
    if (data.size() < MCP_HEADER_LEN)
        return false;

    parsed.source = (static_cast<uint16_t>(data[1]) << 8) | data[0];
    parsed.opcode = data[2];
    parsed.payload = data.data() + MCP_HEADER_LEN;
    parsed.payload_len = data.size() - MCP_HEADER_LEN;
    return true;
}

size_t build_disassociate(uint16_t device_id, uint8_t *out, size_t out_cap)
{
    uint8_t zero_payload[10] = {};
    return build(device_id, MCP_DISASSOCIATE_OPCODE,
                 {zero_payload, sizeof(zero_payload)}, out, out_cap);
}

}  // namespace csrmesh::mcp
