# recsrmesh-cpp

A C++20 library implementing the reverse-engineered CSRMesh BLE mesh protocol.

The library is hardware-agnostic — it requires the caller to provide BLE write and notification hooks, making it portable to any platform with a BLE stack.

The equivalent Python library is [recsrmesh](https://github.com/oyvindkinsey/recsrmesh).

## features

- Full CSRMesh packet framing and crypto (key derivation, HMAC-SHA256, MASP XOR, MCP encryption)
- Send and receive MCP model messages to/from mesh devices
- Device association (claiming) and disassociation
- Unassociated device discovery
- No platform dependencies — BLE I/O is fully abstracted via callbacks

## usage

```cpp
#include <recsrmesh/csrmesh.h>

// Provide a BLE write function for your platform
csrmesh::MeshContext ctx;
csrmesh::init(ctx, my_ble_write_fn, "your-base64-passphrase");

csrmesh::set_rx_callback(ctx, [](uint16_t mcp_source, uint16_t crypto_source,
                                  uint8_t opcode, const uint8_t *payload, size_t len) {
    // handle incoming mesh message
});

// Send a raw MCP model message
csrmesh::send(ctx, dest_id, opcode, payload, payload_len);

// Feed BLE notifications from your platform into the stack
csrmesh::feed_notify(ctx, ch, data, len, now_ms);

// Call periodically to drive retransmits and timeouts
csrmesh::poll(ctx, now_ms);
```

## used by

- [avionmesh-cpp](https://github.com/oyvindkinsey/avionmesh-cpp) — Avi-on mesh command layer built on top of this library
- [esphome-avionmesh](https://github.com/oyvindkinsey/esphome-avionmesh) — ESPHome component for Home Assistant integration

## license

GPL-3.0-or-later — See the `LICENSE` file for details.
