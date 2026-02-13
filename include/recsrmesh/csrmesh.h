#pragma once

#include "crypto.h"
#include "mcp.h"
#include "mcp_crypto.h"
#include "mtl.h"
#include "protocol.h"
#include "types.h"

#include <functional>

namespace csrmesh {

// Callback for decrypted MCP messages
using RxCallback = std::function<void(uint16_t mcp_source, uint16_t crypto_source,
                                      uint8_t opcode, const uint8_t *payload,
                                      size_t payload_len)>;

// Callback for discovered unassociated devices
using DiscoveryCallback = std::function<void(const uint8_t *uuid, size_t uuid_len,
                                             uint32_t uuid_hash)>;

struct MeshContext {
    mtl::Context mtl;
    mtl::BleWriteFn ble_write;

    uint8_t mcp_key[KEY_LEN] = {};
    uint8_t masp_key[KEY_LEN] = {};

    RxCallback rx_cb;

    bool discovering = false;
    DiscoveryCallback discovery_cb;

    protocol::Context *proto = nullptr;

    uint32_t mcp_seq = 0;
};

Error init(MeshContext &ctx, mtl::BleWriteFn ble_write, const char *passphrase);

void set_rx_callback(MeshContext &ctx, RxCallback cb);

void feed_notify(MeshContext &ctx, Characteristic ch,
                 const uint8_t *data, size_t len, uint32_t now_ms);

void poll(MeshContext &ctx, uint32_t now_ms);

Error send(MeshContext &ctx, uint16_t dest_id, uint8_t opcode,
           const uint8_t *payload, size_t payload_len);

Error disassociate(MeshContext &ctx, uint16_t device_id);

Error discover_start(MeshContext &ctx, DiscoveryCallback cb);
void discover_stop(MeshContext &ctx);

Error associate_start(MeshContext &ctx, protocol::Context *proto,
                      uint32_t uuid_hash, uint16_t device_id);
void associate_cancel(MeshContext &ctx);

}  // namespace csrmesh
