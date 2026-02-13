#include "recsrmesh/mtl.h"

#include <algorithm>
#include <cstring>

namespace csrmesh::mtl {

void init(Context &ctx, BleWriteFn write_fn, RxCallback rx_cb)
{
    ctx = {};
    ctx.ble_write = std::move(write_fn);
    ctx.rx_cb = std::move(rx_cb);
}

static void flush_low_buf(Context &ctx)
{
    if (ctx.low_pending && ctx.rx_cb) {
        ctx.rx_cb(ctx.low_buf, ctx.low_buf_len);
    }
    ctx.low_pending = false;
    ctx.low_buf_len = 0;
}

void feed(Context &ctx, Characteristic ch,
          const uint8_t *data, size_t len, uint32_t now_ms)
{
    if (ch == Characteristic::Low) {
        size_t copy_len = std::min(len, MTL_FRAG_SIZE);
        std::memcpy(ctx.low_buf, data, copy_len);
        ctx.low_buf_len = copy_len;
        ctx.low_pending = true;
        ctx.low_timestamp_ms = now_ms;
    } else {
        if (ctx.low_pending) {
            // Concatenate LOW + HIGH fragments and deliver
            uint8_t combined[MTL_MAX_PACKET];
            size_t total = std::min(ctx.low_buf_len + len, MTL_MAX_PACKET);
            std::memcpy(combined, ctx.low_buf, ctx.low_buf_len);
            size_t high_len = total - ctx.low_buf_len;
            std::memcpy(combined + ctx.low_buf_len, data, high_len);

            ctx.low_pending = false;
            ctx.low_buf_len = 0;

            if (ctx.rx_cb)
                ctx.rx_cb(combined, total);
        } else {
            // Standalone HIGH packet
            if (ctx.rx_cb)
                ctx.rx_cb(data, len);
        }
    }
}

void poll(Context &ctx, uint32_t now_ms)
{
    if (!ctx.low_pending)
        return;

    uint32_t elapsed = now_ms - ctx.low_timestamp_ms;
    if (elapsed >= MTL_TIMEOUT_MS)
        flush_low_buf(ctx);
}

Error send(Context &ctx, const uint8_t *data, size_t len, bool write_with_response)
{
    if (!ctx.ble_write)
        return Error::InvalidArg;

    if (len <= MTL_FRAG_SIZE) {
        int ret = ctx.ble_write(Characteristic::High, data, len, write_with_response);
        return ret == 0 ? Error::Ok : Error::BleWrite;
    }

    // Long packet: first 20 bytes on LOW, remainder on HIGH
    int ret = ctx.ble_write(Characteristic::Low, data, MTL_FRAG_SIZE, write_with_response);
    if (ret != 0)
        return Error::BleWrite;

    size_t remaining = len - MTL_FRAG_SIZE;
    ret = ctx.ble_write(Characteristic::High, data + MTL_FRAG_SIZE,
                        remaining, write_with_response);
    return ret == 0 ? Error::Ok : Error::BleWrite;
}

}  // namespace csrmesh::mtl
