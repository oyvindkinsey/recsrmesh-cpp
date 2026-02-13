#pragma once

#include "masp.h"
#include "types.h"

namespace csrmesh::protocol {

enum class State {
    Init = 0,
    WaitAssocResponse,
    PubkeyExchange,
    WaitConfirmResponse,
    WaitRandomResponse,
    WaitDeviceIdAck,
    NetkeyExchange,
    Complete,
    Error,
};

struct Context {
    masp::Context assoc;
    State state = State::Init;
    uint16_t device_id = 0;
    uint8_t pubkey_chunk = 0;
    uint8_t netkey_chunk = 0;
    const char *error = nullptr;
    bool replay_mode = false;
};

// Initialize protocol state machine
Error init(Context &ctx, uint32_t uuid_hash, uint16_t device_id,
           const char *passphrase);

// Get first request packet (ASSOC_REQUEST). Returns length, 0 if wrong state.
size_t get_initial_request(Context &ctx, uint8_t *out, size_t out_cap);

// Process a response (XOR-decoded MASP message).
// Returns length of next request to send, or 0.
size_t process(Context &ctx, const uint8_t *response, size_t response_len,
               uint8_t *out, size_t out_cap);

bool is_complete(const Context &ctx);
bool is_error(const Context &ctx);
const char *state_name(State state);

// Free ECDH context inside the protocol context
void cleanup(Context &ctx);

}  // namespace csrmesh::protocol
