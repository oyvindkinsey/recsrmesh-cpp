#pragma once

#include "types.h"

#include <functional>

namespace csrmesh::mtl {

// BLE write callback: returns 0 on success
using BleWriteFn = std::function<int(Characteristic, const uint8_t *, size_t, bool)>;

// Callback for reassembled packets
using RxCallback = std::function<void(const uint8_t *, size_t)>;

struct Context {
    // BLE write hook
    BleWriteFn ble_write;

    // RX reassembly
    uint8_t low_buf[MTL_FRAG_SIZE] = {};
    size_t low_buf_len = 0;
    bool low_pending = false;
    uint32_t low_timestamp_ms = 0;

    // RX callback
    RxCallback rx_cb;
};

void init(Context &ctx, BleWriteFn write_fn, RxCallback rx_cb);

// Feed a BLE notification (characteristic + data).
void feed(Context &ctx, Characteristic ch,
          const uint8_t *data, size_t len, uint32_t now_ms);

// Poll for fragment timeout.
void poll(Context &ctx, uint32_t now_ms);

// TX: fragment and send a packet via BLE hooks.
Error send(Context &ctx, const uint8_t *data, size_t len, bool write_with_response);

}  // namespace csrmesh::mtl
