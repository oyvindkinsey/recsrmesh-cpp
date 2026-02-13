#include "recsrmesh/protocol.h"
#include "recsrmesh/crypto.h"

#include <cstring>

namespace csrmesh::protocol {

static const char *state_names[] = {
    "INIT",
    "WAIT_ASSOC_RESPONSE",
    "PUBKEY_EXCHANGE",
    "WAIT_CONFIRM_RESPONSE",
    "WAIT_RANDOM_RESPONSE",
    "WAIT_DEVICE_ID_ACK",
    "NETKEY_EXCHANGE",
    "COMPLETE",
    "ERROR",
};

Error init(Context &ctx, uint32_t uuid_hash, uint16_t device_id,
           const char *passphrase)
{
    ctx = {};
    ctx.device_id = device_id;
    ctx.state = State::Init;

    auto err = masp::init(ctx.assoc, passphrase);
    if (err != Error::Ok)
        return err;

    masp::set_target(ctx.assoc, uuid_hash);
    return Error::Ok;
}

static size_t build_next_request(Context &ctx, uint8_t *out, size_t out_cap)
{
    switch (ctx.state) {
    case State::PubkeyExchange:
        ctx.assoc.pubkey_chunk_index = ctx.pubkey_chunk;
        return masp::build_pubkey_packet(ctx.assoc, out, out_cap);

    case State::WaitConfirmResponse:
        return masp::build_confirm_request(ctx.assoc, out, out_cap);

    case State::WaitRandomResponse:
        return masp::build_random_request(ctx.assoc, out, out_cap);

    case State::WaitDeviceIdAck:
        return masp::build_device_id_packet(ctx.assoc, ctx.device_id, out, out_cap);

    case State::NetkeyExchange:
        ctx.assoc.netkey_chunk_index = ctx.netkey_chunk;
        return masp::build_netkey_packet(ctx.assoc, out, out_cap);

    default:
        return 0;
    }
}

size_t get_initial_request(Context &ctx, uint8_t *out, size_t out_cap)
{
    if (ctx.state != State::Init)
        return 0;

    ctx.state = State::WaitAssocResponse;
    return masp::build_assoc_request(ctx.assoc, out, out_cap);
}

size_t process(Context &ctx, const uint8_t *response, size_t response_len,
               uint8_t *out, size_t out_cap)
{
    if (ctx.state == State::Error || !response || response_len == 0)
        return 0;

    uint8_t opcode = response[0];

    // Re-encode for parsers that XOR internally
    uint8_t wire[64];
    if (response_len > sizeof(wire))
        return 0;
    crypto::xor_masp_packet(response, wire, response_len);

    switch (ctx.state) {
    case State::WaitAssocResponse: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::AssocResponse))
            return 0;

        int confirm_type;
        if (!masp::parse_assoc_response(ctx.assoc, wire, response_len, confirm_type)) {
            ctx.error = "ASSOC rejected";
            ctx.state = State::Error;
            return 0;
        }
        ctx.state = State::PubkeyExchange;
        return build_next_request(ctx, out, out_cap);
    }

    case State::PubkeyExchange: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::PubkeyResponse))
            return 0;

        if (!masp::parse_pubkey_response(ctx.assoc, wire, response_len)) {
            ctx.error = "PUBKEY_RESPONSE parse failed";
            ctx.state = State::Error;
            return 0;
        }

        ctx.pubkey_chunk++;
        if (ctx.pubkey_chunk >= 6) {
            if (!ctx.replay_mode) {
                auto err = masp::compute_shared_secret(ctx.assoc);
                if (err != Error::Ok) {
                    ctx.error = "ECDH computation failed";
                    ctx.state = State::Error;
                    return 0;
                }
            }
            ctx.state = State::WaitConfirmResponse;
        }
        return build_next_request(ctx, out, out_cap);
    }

    case State::WaitConfirmResponse: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::ConfirmResponse))
            return 0;

        if (!masp::parse_confirm_response(ctx.assoc, wire, response_len)) {
            ctx.error = "CONFIRM_RESPONSE parse failed";
            ctx.state = State::Error;
            return 0;
        }
        ctx.state = State::WaitRandomResponse;
        return build_next_request(ctx, out, out_cap);
    }

    case State::WaitRandomResponse: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::RandomResponse))
            return 0;

        if (ctx.replay_mode) {
            std::memcpy(ctx.assoc.device_random, response + 5, 8);
            ctx.assoc.has_device_random = true;
        } else {
            if (!masp::parse_random_response(ctx.assoc, wire, response_len)) {
                ctx.error = "RANDOM_RESPONSE verification failed";
                ctx.state = State::Error;
                return 0;
            }
        }
        ctx.state = State::WaitDeviceIdAck;
        return build_next_request(ctx, out, out_cap);
    }

    case State::WaitDeviceIdAck: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::DeviceIdAck))
            return 0;

        ctx.state = State::NetkeyExchange;
        return build_next_request(ctx, out, out_cap);
    }

    case State::NetkeyExchange: {
        if (opcode != static_cast<uint8_t>(masp::Opcode::NetkeyAck))
            return 0;

        ctx.netkey_chunk++;
        if (ctx.netkey_chunk >= 2) {
            ctx.state = State::Complete;
            return 0;
        }
        return build_next_request(ctx, out, out_cap);
    }

    default:
        return 0;
    }
}

bool is_complete(const Context &ctx) { return ctx.state == State::Complete; }
bool is_error(const Context &ctx) { return ctx.state == State::Error; }

const char *state_name(State state)
{
    auto idx = static_cast<size_t>(state);
    if (idx < sizeof(state_names) / sizeof(state_names[0]))
        return state_names[idx];
    return "UNKNOWN";
}

void cleanup(Context &ctx)
{
    masp::cleanup(ctx.assoc);
}

}  // namespace csrmesh::protocol
