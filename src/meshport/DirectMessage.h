// Direct messages over meshport frames.
//
// Each device has an X25519 identity (32-byte private key, 32-byte public key) and a
// 32-bit node number derived from its public key. A direct message is sent as a normal
// Meshtastic frame on port kPortDirect (Meshtastic's PRIVATE_APP range). Standard
// Meshtastic nodes relay it but cannot read the payload, because the payload is also
// end-to-end encrypted with the sender/recipient key.
//
// Payload layout (after the frame's channel encryption is removed):
//   [0]      format version (1)
//   [1..32]  sender public key
//   [33..40] message counter, little-endian (must increase per sender)
//   [41..]   ciphertext || 16-byte tag
// AAD for the end-to-end layer is from-node (4, LE) || to-node (4, LE), so a message
// cannot be replayed to a different recipient.
#pragma once

#include "MeshtasticFrame.h"
#include "SecureDirect.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace meshport {

constexpr uint32_t kPortDirect = 256;   // Meshtastic PRIVATE_APP
constexpr uint8_t kDirectVersion = 1;
constexpr size_t kDirectHeaderLen = 41; // version + pubkey + counter

struct Identity {
    uint8_t priv[32];
    uint8_t pub[32];
};

// Build an identity from a 32-byte random seed (the seed is the private key).
bool identityFromSeed(const uint8_t seed[32], Identity &id);

// Node number from the public key: first 4 bytes, little-endian. Stable for a given key.
uint32_t nodeNumberFromPublicKey(const uint8_t pub[32]);

// Remembers the highest counter accepted from each sender. Rejects replays.
class ReplayGuard {
public:
    // Returns true if the counter is new for this sender, and records it.
    bool accept(const uint8_t senderPub[32], uint64_t counter);

private:
    struct Entry {
        uint8_t pub[32];
        uint64_t last;
    };
    std::vector<Entry> entries_;
};

// Build a complete frame carrying `text` to a peer. `counter` must increase for each message to this peer.
bool buildDirectFrame(const uint8_t channelPsk[32], size_t channelPskLen, uint8_t channelHash,
                      const Identity &me, uint32_t toNode, const uint8_t peerPub[32], uint64_t counter,
                      const std::string &text, uint32_t packetId, std::vector<uint8_t> &frame);

// Parse and verify a frame. Fills the sender, text, and counter. Returns false if the frame is
// not a direct message for this device, fails authentication, or is a replay.
bool openDirectFrame(const uint8_t channelPsk[32], size_t channelPskLen, const Identity &me,
                     const uint8_t *frame, size_t len, ReplayGuard &guard, uint32_t &fromNode,
                     std::string &text);

} // namespace meshport
