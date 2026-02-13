#include "recsrmesh/csrmesh.h"

#include <cstring>

namespace csrmesh {

// Forward declarations
static void on_mtl_packet(const uint8_t *data, size_t len, MeshContext &ctx);
static void handle_discovery(MeshContext &ctx, const uint8_t *data, size_t len);
static bool handle_masp(MeshContext &ctx, const uint8_t *data, size_t len);
static void handle_mcp(MeshContext &ctx, const uint8_t *data, size_t len);

Error init(MeshContext &ctx, mtl::BleWriteFn ble_write, const char *passphrase)
{
    ctx = {};
    ctx.ble_write = ble_write;

    // MCP key: SHA256(passphrase + "\x00MCP"), reversed, first 16
    size_t pass_len = std::strlen(passphrase);
    uint8_t mcp_input[256];
    if (pass_len + 4 > sizeof(mcp_input))
        return Error::BufferTooSmall;
    std::memcpy(mcp_input, passphrase, pass_len);
    mcp_input[pass_len] = '\0';
    mcp_input[pass_len + 1] = 'M';
    mcp_input[pass_len + 2] = 'C';
    mcp_input[pass_len + 3] = 'P';
    auto err = mcp_crypto::generate_key({mcp_input, pass_len + 4}, ctx.mcp_key);
    if (err != Error::Ok)
        return err;

    // MASP key: derive_key("", "\x00MASP")
    const char masp_salt[] = "\x00MASP";
    err = crypto::derive_key("", masp_salt, sizeof(masp_salt) - 1, ctx.masp_key);
    if (err != Error::Ok)
        return err;

    // Capture ctx pointer in lambda for MTL callback
    mtl::init(ctx.mtl, ble_write, [&ctx](const uint8_t *data, size_t len) {
        on_mtl_packet(data, len, ctx);
    });

    return Error::Ok;
}

void set_rx_callback(MeshContext &ctx, RxCallback cb)
{
    ctx.rx_cb = std::move(cb);
}

void feed_notify(MeshContext &ctx, Characteristic ch,
                 const uint8_t *data, size_t len, uint32_t now_ms)
{
    mtl::feed(ctx.mtl, ch, data, len, now_ms);
}

void poll(MeshContext &ctx, uint32_t now_ms)
{
    mtl::poll(ctx.mtl, now_ms);
}

Error send(MeshContext &ctx, uint16_t dest_id, uint8_t opcode,
           const uint8_t *payload, size_t payload_len)
{
    uint8_t mcp_buf[64];
    size_t mcp_len = mcp::build(dest_id, opcode,
                                 {payload, payload_len},
                                 mcp_buf, sizeof(mcp_buf));
    if (mcp_len == 0)
        return Error::BufferTooSmall;

    uint32_t seq;
    auto err = mcp_crypto::random_seq(seq);
    if (err != Error::Ok)
        return err;

    uint8_t enc_buf[80];
    size_t enc_len = mcp_crypto::make_packet(ctx.mcp_key, seq,
                                              {mcp_buf, mcp_len},
                                              enc_buf, sizeof(enc_buf));
    if (enc_len == 0)
        return Error::Crypto;

    return mtl::send(ctx.mtl, enc_buf, enc_len, false);
}

Error disassociate(MeshContext &ctx, uint16_t device_id)
{
    uint8_t mcp_buf[16];
    size_t mcp_len = mcp::build_disassociate(device_id, mcp_buf, sizeof(mcp_buf));
    if (mcp_len == 0)
        return Error::BufferTooSmall;

    uint32_t seq;
    auto err = mcp_crypto::random_seq(seq);
    if (err != Error::Ok)
        return err;

    uint8_t enc_buf[80];
    size_t enc_len = mcp_crypto::make_packet(ctx.mcp_key, seq,
                                              {mcp_buf, mcp_len},
                                              enc_buf, sizeof(enc_buf));
    if (enc_len == 0)
        return Error::Crypto;

    return mtl::send(ctx.mtl, enc_buf, enc_len, false);
}

Error discover_start(MeshContext &ctx, DiscoveryCallback cb)
{
    ctx.discovering = true;
    ctx.discovery_cb = std::move(cb);

    // Build and send DEVICE_ID_ANNOUNCE with hash=0 (broadcast)
    masp::Context tmp = {};
    masp::set_target(tmp, 0);

    uint8_t announce[18];
    size_t announce_len = masp::build_device_id_announce(tmp, announce, sizeof(announce));
    if (announce_len == 0)
        return Error::Crypto;

    uint8_t packet[32];
    size_t packet_len;
    auto err = crypto::add_packet_mac({announce, announce_len},
                                       ctx.masp_key, 55,
                                       packet, &packet_len);
    if (err != Error::Ok)
        return err;

    return mtl::send(ctx.mtl, packet, packet_len, false);
}

void discover_stop(MeshContext &ctx)
{
    ctx.discovering = false;
    ctx.discovery_cb = nullptr;
}

Error associate_start(MeshContext &ctx, protocol::Context *proto,
                      uint32_t /*uuid_hash*/, uint16_t /*device_id*/)
{
    if (ctx.proto)
        return Error::Busy;

    uint8_t request[32];
    size_t req_len = protocol::get_initial_request(*proto, request, sizeof(request));
    if (req_len == 0)
        return Error::ProtoState;

    uint8_t packet[64];
    size_t packet_len;
    auto err = crypto::add_packet_mac({request, req_len}, proto->assoc.masp_key, 55,
                                       packet, &packet_len);
    if (err != Error::Ok)
        return err;

    err = mtl::send(ctx.mtl, packet, packet_len, false);
    if (err != Error::Ok)
        return err;

    ctx.proto = proto;
    return Error::Ok;
}

void associate_cancel(MeshContext &ctx)
{
    if (ctx.proto) {
        protocol::cleanup(*ctx.proto);
        ctx.proto = nullptr;
    }
}

// ---- Internal handlers ----

static void on_mtl_packet(const uint8_t *data, size_t len, MeshContext &ctx)
{
    if (ctx.discovering)
        handle_discovery(ctx, data, len);

    if (ctx.proto) {
        if (handle_masp(ctx, data, len))
            return;
    }

    handle_mcp(ctx, data, len);
}

static void handle_discovery(MeshContext &ctx, const uint8_t *data, size_t len)
{
    if (!ctx.discovery_cb)
        return;

    size_t payload_len;
    bool valid;
    crypto::verify_packet_mac({data, len}, ctx.masp_key, &payload_len, &valid);
    if (!valid)
        return;

    uint8_t message[64];
    if (payload_len > sizeof(message))
        return;
    crypto::xor_masp_packet(data, message, payload_len);

    if (payload_len < 17 ||
        message[0] != static_cast<uint8_t>(masp::Opcode::UuidAnnounce))
        return;

    const uint8_t *uuid_bytes = message + 1;
    uint32_t uuid_hash = crypto::uuid_to_hash31({uuid_bytes, 16});

    ctx.discovery_cb(uuid_bytes, 16, uuid_hash);
}

static bool handle_masp(MeshContext &ctx, const uint8_t *data, size_t len)
{
    auto *proto = ctx.proto;

    size_t payload_len;
    bool valid;
    crypto::verify_packet_mac({data, len}, proto->assoc.masp_key, &payload_len, &valid);
    if (!valid)
        return false;

    uint8_t message[64];
    if (payload_len > sizeof(message))
        return false;
    crypto::xor_masp_packet(data, message, payload_len);

    uint8_t next_request[32];
    size_t next_len = protocol::process(*proto, message, payload_len,
                                         next_request, sizeof(next_request));

    if (protocol::is_complete(*proto) || protocol::is_error(*proto)) {
        ctx.proto = nullptr;
        return true;
    }

    if (next_len > 0) {
        uint8_t packet[64];
        size_t packet_len;
        auto err = crypto::add_packet_mac({next_request, next_len},
                                           proto->assoc.masp_key, 55,
                                           packet, &packet_len);
        if (err == Error::Ok)
            mtl::send(ctx.mtl, packet, packet_len, false);
        return true;
    }

    return false;
}

static void handle_mcp(MeshContext &ctx, const uint8_t *data, size_t len)
{
    if (!ctx.rx_cb)
        return;

    mcp_crypto::Decrypted result;
    if (mcp_crypto::decrypt_packet(ctx.mcp_key, {data, len}, result) != Error::Ok)
        return;

    mcp::Parsed parsed;
    if (!mcp::parse({result.decrypted, result.decrypted_len}, parsed))
        return;

    ctx.rx_cb(parsed.source, result.source, parsed.opcode,
              parsed.payload, parsed.payload_len);
}

}  // namespace csrmesh
